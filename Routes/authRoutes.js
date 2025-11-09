const { Router } = require("express");
const authMiddelware = require("../Middelwares/authMiddelware");
const { userSignUp, userLogin, refreshToken, getUser, googleCallBack, userLogout, userResetPassword } = require("../Controllers/userController");
const passport = require("passport");
require('../Controllers/passport.config')

const authRoutes = Router()

authRoutes.get('/' , authMiddelware , (req, res) => {res.send('Main get')})
authRoutes.post('/api/signup' , userSignUp)
authRoutes.post('/api/login' , userLogin)
authRoutes.post('/api/refresh-token' , refreshToken)
authRoutes.get('/api/profile' , authMiddelware , getUser)
authRoutes.post('/api/logout' , authMiddelware , userLogout)
authRoutes.post('/api/reset-password' , authMiddelware , userResetPassword)
authRoutes.get('/auth/google/callback' , passport.authenticate('google', {
    failureRedirect: '/auth-fail', // A simple failure route
    session: false // Ensure stateless
}), googleCallBack)
authRoutes.get(
    '/auth/google',
    passport.authenticate('google', { 
        scope: ['profile', 'email'], // <-- THIS IS THE REQUIRED FIX!
        session: false // Keep session: false for JWT flow
    })
);



module.exports = authRoutes