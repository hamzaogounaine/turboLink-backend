// passport.config.js - CORRECTED
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require("../Models/User");


passport.use(
    new GoogleStrategy (
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: "/auth/google/callback",
            // Crucial: Tell Passport NOT to use sessions for this strategy
            session: false, 
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const googleId = profile.id;
                // Safely access the email from the profile object
                const email = profile.emails && profile.emails[0].value; 

                let user = await User.findOne({
                    $or: [{ googleId: googleId }, { email: email }]
                });
                
                if (!user) {
                    // 1. User not found: Create a new user record
                    user = await User.create({
                        googleId: googleId,
                        email: email,
                        // Ensure the username generation is simple and non-conflicting
                        username: profile.displayName.replace(/\s/g, '').toLowerCase() + Math.floor(Math.random() * 100), 
                        isGoogleUser: true
                    });
                } else if (!user.googleId) {
                    // 2. Existing local user: Link the Google ID for future social logins
                    user.googleId = googleId;
                    await user.save();
                }

                // 3. Authentication successful, return the user object
                return done(null, user);

            } catch(err) {
                // Pass any errors during DB operations to Passport's error handler
                return done(err, false);
            }
        }
    )
);