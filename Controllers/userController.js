const User = require("../Models/User");
const jwt = require("jsonwebtoken");
const {
  generateTokens,
  sendAuthResponse,
  handleErrors,
  generateEmailVeficationToken,
} = require("../utils/authUtils");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const {
  resendEmailVerificationLink,
  sendVerificationLink,
} = require("../utils/sendEmails");
const getVerificationEmailTemplate = require("../emails/deviceVerificationTemplates");
const getAccountVerificationEmailTemplate = require("../emails/emailVerficationTemplates");
const { email } = require("zod");
const { OAuth2Client } = require("google-auth-library");

const getUser = async (req, res) => {
  const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;

  // 1. Check for the Authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ error: "Access token missing or invalid format" });
  }

  // 2. Extract the token
  const accessToken = authHeader.split(" ")[1];

  try {
    // 3. Verify the access token
    const payload = jwt.verify(accessToken, ACCESS_TOKEN_SECRET);
    const userId = payload.userId;

    // 4. Find the user in the database
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // 5. Prepare user object (similar to sendAuthResponse)
    const userResponse = user.toObject({ getters: true });
    delete userResponse.refresh_token;
    delete userResponse.last_login_ip; // Ensure sensitive fields are removed

    // 6. Return the sanitized user object
    return res.status(200).json({ user: userResponse });
  } catch (err) {
    // This catches expired/invalid token errors
    console.error("Access token verification failed:", err.message);

    return res.status(401).json({ error: "Access token expired or invalid" });
  }
};

const userSignUp = async (req, res) => {
  const { username, email, password, firstName, lastName, confirmPassword } =
    req.body;
  const lang = req.cookies["NEXT_LOCALE"];

  const errors = {};
  try {
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });

    if (existingUser) {
      if (existingUser.email === email) {
        errors.email = "emailTaken";
      }
      if (existingUser.username === username) {
        errors.username = "usernameTaken";
      }
    }

    if (Object.keys(errors).length > 0) {
      return res.status(400).json({ errors });
    }

    const createdUser = await User.create({
      email,
      username,
      password,
      first_name: firstName,
      last_name: lastName,
    });

    const { accessToken, refreshToken } = generateTokens(createdUser);

    const updatedUser = await User.findByIdAndUpdate(
      createdUser._id,
      { refresh_token: refreshToken },
      { new: true } // returns the updated document
    );

    const verificationToken = generateEmailVeficationToken(createdUser._id);
    const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;

    const { html, subject } = getAccountVerificationEmailTemplate(
      lang,
      createdUser.username,
      verificationLink
    );

    const emailSent = await sendVerificationLink(
      (to = createdUser.email),
      subject,
      (body = html)
    );
    console.log(emailSent);

    if (!emailSent) {
      return res
        .status(400)
        .json({ message: "Error while sending verification link" });
    }

    return sendAuthResponse(
      res,
      updatedUser,
      accessToken,
      refreshToken,
      (message = "accountCreated")
    );
  } catch (err) {
    console.log(err);
    const errors = handleErrors(err);
    return res.status(404).json(errors);
  }
};

const userLogin = async (req, res) => {
  const { email, password } = req.body;
  const clientIP = req.ip;
  const lang = req.cookies["NEXT_LOCALE"];

  try {
    const user = await User.login(email, password);

    if (user.last_login_ip &&   user.last_login_ip !== clientIP) {
      const code = crypto.randomInt(100000, 999999);
      const codeExpiration = Date.now() + 15 * 60 * 1000; // 15 minutes

      await User.findByIdAndUpdate(user._id, {
        ip_verification_code: code,
        ip_verification_code_expiration: codeExpiration,
      });
      const { html, subject } = getVerificationEmailTemplate(
        lang,
        user.username,
        clientIP,
        code
      );
      await sendVerificationLink(to = user.email , subject  , body = html)

      return res.status(200).json({
        message: "mustVerifyIp",
        codeSent: true,
      });
    }

    const { accessToken, refreshToken } = generateTokens(user);

    const updatedUser = await User.findByIdAndUpdate(
      user._id,
      { refresh_token: refreshToken, last_login_ip: clientIP },
      { new: true } // returns the updated document
    );

    return sendAuthResponse(
      res,
      updatedUser,
      accessToken,
      refreshToken,
      (message = "loginSuccess")
    );
  } catch (err) {
    if (err.message === "invalidCredentials") {
      return res.status(404).json("invalidCredentials");
    }
    console.log(err);
    const errors = handleErrors(err);
    return res.status(500).json(errors);
  }
};

const userLogout = async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.clearCookie("refreshToken");
    return res.status(400).json({ message: "malformedTokenHeader" });
  }

  const accessToken = authHeader.split(" ")[1];
  let userId;

  try {
    const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, {
      ignoreExpiration: true,
    });
    userId = decoded.userId;
  } catch (err) {
    res.clearCookie("refreshToken");
    console.error("Logout: Invalid access token signature/format:", err);
    return res.status(401).json({ message: "invalidToken" });
  }

  try {
    await User.findByIdAndUpdate(userId, { refresh_token: null });

    res.clearCookie("refreshToken");

    return res.status(200).json({ message: "loggedOut" });
  } catch (err) {
    console.error("Logout Database/Cookie Error:", err);
    // Use 500 for unexpected server/DB failures
    return res.status(500).json({ message: "unexpectedError" });
  }
};

const userResetPassword = async (req, res) => {
  const { oldPassword, newPassword, newConfirmationPassword } = req.body;
  const authHeader = req.headers.authorization;
  const accessToken = authHeader && authHeader.split(" ")[1];

  // --- 1. Initial Checks ---

  if (!accessToken) {
    // FIX: .message() is not a standard Express method, use .send() or .json()
    return res.status(401).json({ message: "No access token provided" });
  }

  // Basic input validation
  if (!oldPassword || !newPassword || !newConfirmationPassword) {
    return res
      .status(400)
      .json({ message: "All password fields are required." });
  }

  if (newPassword !== newConfirmationPassword) {
    return res.status(400).json({
      message: "New password and confirmation password do not match.",
    });
  }

  // --- 2. Token Verification and User Retrieval ---

  try {
    const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
    const userId = decoded.userId;
    const user = await User.findById(userId);

    if(user.is_google_user) {
      return res.status(401).json({message : 'Not authorized'})
    }

    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // --- 3. Verify Old Password (Completing your line) ---

    // Check if the old password provided matches the hash in the database
    const isPasswordValid = await bcrypt.compare(oldPassword, user.password);

    if (!isPasswordValid) {
      return res
        .status(400)
        .json({ message: "The current password is incorrect." });
    }

    // Optional: Check if the new password is the same as the old one
    if (await bcrypt.compare(newPassword, user.password)) {
      return res.status(400).json({
        message: "The new password must be different from the old password.",
      });
    }

    // --- 4. Hash New Password and Update ---

    // Hash the new password before storing it
    user.password = newPassword;
    user.refreshToken = undefined;
    res.clearCookie("refreshToken");
    await user.save(); // Save the updated user document

    return res.status(200).json({ message: "Password updated successfully." });
  } catch (err) {
    // Handles errors from jwt.verify (e.g., expired or invalid token) or database errors
    if (err.name === "TokenExpiredError" || err.name === "JsonWebTokenError") {
      return res
        .status(401)
        .json({ message: "Invalid or expired access token." });
    }
    console.error("Password reset error:", err);
    return res
      .status(500)
      .json({ message: "An internal server error occurred." });
  }
};

const googleCallBack = async (req, res) => {
  const CLIENT_REDIRECT_URL = `${process.env.FRONTEND_URL}/dashboard`; // Replace with your actual frontend URL
  try {
    const user = req.user;

    if (!user) {
      return res.redirect(`${CLIENT_REDIRECT_URL}?error=auth_failed`);
    }

    const { accessToken, refreshToken } = generateTokens(user);

    const updatedUser = await User.findByIdAndUpdate(
      user._id,
      { refresh_token: refreshToken }, // CORRECTED FIELD NAME to match other logic
      { new: true }
    );

    // 3. SET THE HTTP-ONLY REFRESH TOKEN COOKIE
    // We replicate the cookie-setting part of sendAuthResponse here.
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true, // Recommended for security (cannot be read by JS)
      // IMPORTANT: When running on different localhost ports (HTTP),
      // you must *not* set secure: true or SameSite: 'None'.
      // Leaving SameSite unset or setting to 'Lax' is the best practice here.
      // If 'Lax' doesn't work, try removing the sameSite property completely.
      // sameSite: "Lax",
      secure: process.env.NODE_ENV === "prod" && true,
      sameSite: process.env.NODE_ENV === "prod" ? "None" : "Lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.redirect(
      `${CLIENT_REDIRECT_URL}?accessToken=${accessToken}&success=true`
    );
  } catch (err) {
    console.error("Error during Google OAuth flow:", err);
    // Redirect to a frontend failure page
    return res.redirect(
      `${CLIENT_REDIRECT_URL}?success=false&error=server_error`
    );
  }
};

const updateProfile = async (req, res) => {
  const { userId, firstName, lastName, email, phoneNumber, password } = req.body;
  lang = req.cookies['NEXT_LOCALE']

  // 1. INPUT VALIDATION
  if (!userId || !password) {
    return res.status(400).json({ message: "User ID and password are required." });
  }

  try {
    // 2. FETCH USER (Select password for verification)
    const user = await User.findById(userId).select("+password");

    // 3. SANITY CHECKS (Order matters!)
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    if (user.is_google_user) {
      return res.status(403).json({ message: "Google users cannot update profile via this endpoint." });
    }

    // 4. VERIFY PASSWORD
    const pwdIsValid = await bcrypt.compare(password, user.password);
    if (!pwdIsValid) {
      return res.status(403).json({ message: "Incorrect password." });
    }

    // 5. HANDLE UPDATES
    let emailChanged = false;
    
    // Update basic fields
    if (firstName) user.first_name = firstName;
    if (lastName) user.last_name = lastName;
    if (phoneNumber) user.phone_number = phoneNumber;

    // Handle Email Specific Logic
    if (email && email !== user.email) {
      emailChanged = true;
      
      // OPTION A (Safer): Don't change main email yet. Store in temp field.
      // user.temp_email = email; 
      
      // OPTION B (Your logic, but working): Update email and mark unverified.
      // WARNING: If they typo the email, they are locked out until they contact support.
      user.email = email;
      user.is_email_verified = false; // Assuming you have this field
    }

    // 6. SAVE (Triggers Mongoose validators)
    const updatedUser = await user.save();

    // 7. SEND VERIFICATION (Only if email changed)
    if (emailChanged) {
      const verificationToken = generateEmailVeficationToken(updatedUser._id);
      const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;

      const { html, subject } = getAccountVerificationEmailTemplate(
        lang, // Now defined
        updatedUser.username || updatedUser.first_name,
        verificationLink
      );

      try {
         sendVerificationLink(updatedUser.email, subject, html);
      } catch (emailErr) {
        console.error("Failed to send verification email:", emailErr);
        // Don't fail the request, but log it. 
        // Optionally return a warning in the response.
      }
    }

    return res.status(200).json({
      message: emailChanged 
        ? "Profile updated. Please verify your new email." 
        : "Profile updated successfully",
      user: updatedUser,
    });

  } catch (err) {
    console.error("Profile update error:", err);
    return res.status(500).json({ message: "Server error during profile update." });
  }
};


const updateGoogleUsersProfile = async (req, res) => {
  const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
  const { userId,  firstName, lastName, phoneNumber , accessToken } = req.body;

  if (!userId) {
    return res.status(400).json({ message: "User ID is required." });
  }

  if (!accessToken) {
    return res.status(401).json({ message: "Google re-authentication required." });
  }

  try {
    const googleUser = await client.getTokenInfo(accessToken);
    console.log('googleUser' , googleUser)
    // 🔎 Find & update in one query
    const updatedUser = await User.findOneAndUpdate(
      { _id: userId, googleId: googleUser.sub },
      {
        $set: {
          ...(firstName && { first_name: firstName }),
          ...(lastName && { last_name: lastName }),
          ...(phoneNumber && { phone_number: phoneNumber }),
        },
      },
      { new: true, runValidators: true }
    );

    // ❌ If no user was matched (wrong googleId or no user)
    if (!updatedUser) {
      return res.status(404).json({ message: "User not found or Google verification failed." });
    }

    return res.status(200).json({
      message: "Profile updated successfully.",
      user: updatedUser,
    });
  } catch (err) {
    console.error("Profile update error:", err);
    return res.status(500).json({ message: "Server error while updating profile." });
  }
};


const verifyEmail = async (req, res) => {
  const { token } = req.body;
  const jsonSecret = process.env.EMAIL_VERIFICATION_TOKEN_SECRET;

  if (!token) {
    return res.status(404).json({ message: "No token found" });
  }
  try {
    const decoded = jwt.verify(token, jsonSecret);

    if (decoded.type !== "email_verification") {
      return res.status(404).json("Invalid token");
    }

    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).json("No user found");
    }

    if (user.is_email_verified) {
      return res.status(200).json({ message: "Email already verified" });
    }

    user.is_email_verified = true;
    await user.save();
  } catch (err) {
    return res.status(403).json(err);
  }
};

module.exports = {
  userSignUp,
  userLogin,
  userLogout,
  getUser,
  googleCallBack,
  userResetPassword,
  updateProfile,
  verifyEmail,
  updateGoogleUsersProfile
};
