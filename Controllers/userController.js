const User = require("../Models/User");
const jwt = require("jsonwebtoken");
const { generateTokens, sendAuthResponse } = require("../utils/authUtils");
const bcrypt = require('bcrypt')

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
    delete userResponse.password; // Ensure sensitive fields are removed

    // 6. Return the sanitized user object
    return res.status(200).json({ user: userResponse });
  } catch (err) {
    // This catches expired/invalid token errors
    console.error("Access token verification failed:", err.message);

    return res.status(401).json({ error: "Access token expired or invalid" });
  }
};

const userSignUp = async (req, res) => {
  const { username, email, password } = req.body;

  try {
    

    const createdUser = await User.create({ email, username, password });

    const { accessToken, refreshToken } = generateTokens(createdUser);

    const updatedUser = await User.findByIdAndUpdate(
      createdUser._id,
      { refresh_token: refreshToken },
      { new: true } // returns the updated document
    );

    return sendAuthResponse(res, updatedUser, accessToken, refreshToken, message='accountCreated');
  } catch (err) {
    console.log(err);
    const errors = handleErrors(err);
    return res.status(404).json(errors);
  }
};

const userLogin = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.login(email, password);
    const { accessToken, refreshToken } = generateTokens(user);

    const updatedUser = await User.findByIdAndUpdate(
      user._id,
      { refresh_token: refreshToken },
      { new: true } // returns the updated document
    );
    return sendAuthResponse(res, updatedUser, accessToken, refreshToken, message='loginSuccess' );
  } catch (err) {
    if (err.message === "invalidCredentials") {
      return res.status(404).json(err.message);
    }
    const errors = handleErrors(err);
    return res.status(404).json(errors);
  }
};

const refreshToken = async (req, res) => {
  const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(403).json({ error: "Refresh token not provided" });
  }

  try {
    // Use promisified version or try-catch with callback
    const payload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);

    const user = await User.findById(payload.userId);
    if (!user || user.refresh_token !== refreshToken) {
      return res.status(403).json({ error: "Invalid refresh token" });
    }

    // Generate new tokens
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user);

    // Save new refresh token to database
    user.refresh_token = newRefreshToken;
    await user.save();

    // Send response with new tokens
    return sendAuthResponse(res, user, accessToken, newRefreshToken);
  } catch (err) {
    console.error("Refresh token error:", err);
    return res.status(403).json({ error: "Invalid or expired refresh token" });
  }
};

const userLogout = async (req , res) => {
  res.clearCookie('refreshToken');
  return res.status(200).json({message : 'loggedout'})
}
const userResetPassword = async (req, res) => {
  const { oldPassword, newPassword, newConfirmationPassword } = req.body;
  const authHeader = req.headers.authorization;
  const accessToken = authHeader && authHeader.split(' ')[1];

  // --- 1. Initial Checks ---

  if (!accessToken) {
    // FIX: .message() is not a standard Express method, use .send() or .json()
    return res.status(401).json({ message: 'No access token provided' });
  }

  // Basic input validation
  if (!oldPassword || !newPassword || !newConfirmationPassword) {
    return res.status(400).json({ message: 'All password fields are required.' });
  }

  if (newPassword !== newConfirmationPassword) {
    return res.status(400).json({ message: 'New password and confirmation password do not match.' });
  }

  // --- 2. Token Verification and User Retrieval ---
  
  try {
    const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
    const userId = decoded.userId;
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    // --- 3. Verify Old Password (Completing your line) ---
    
    // Check if the old password provided matches the hash in the database
    const isPasswordValid = await bcrypt.compare(oldPassword, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'The current password is incorrect.' });
    }

    // Optional: Check if the new password is the same as the old one
    if (await bcrypt.compare(newPassword, user.password)) {
        return res.status(400).json({ message: 'The new password must be different from the old password.' });
    }
    
    // --- 4. Hash New Password and Update ---
    
    // Hash the new password before storing it
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update the password field in the database
    user.password = hashedPassword;
    await user.save(); // Save the updated user document

    // --- 5. Success Response ---
    
    // Note: You should generally invalidate any existing refresh tokens here 
    // to force a full re-login on all devices after a password change.
    // (This step is omitted for brevity but recommended for security.)

    return res.status(200).json({ message: 'Password updated successfully.' });
    
  } catch (err) {
    // Handles errors from jwt.verify (e.g., expired or invalid token) or database errors
    if (err.name === 'TokenExpiredError' || err.name === 'JsonWebTokenError') {
        return res.status(401).json({ message: 'Invalid or expired access token.' });
    }
    console.error("Password reset error:", err);
    return res.status(500).json({ message: 'An internal server error occurred.' });
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
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // 4. PERFORM THE FINAL REDIRECT TO THE FRONTEND
    // The frontend only needs the short-lived access token and success status from the URL.
    return res.redirect(
        `${CLIENT_REDIRECT_URL}?accessToken=${accessToken}&success=true`
    );

  } catch (err) {
    console.error("Error during Google OAuth flow:", err);
    // Redirect to a frontend failure page
    return res.redirect(`${CLIENT_REDIRECT_URL}?success=false&error=server_error`);
  }
};

module.exports = {
  userSignUp,
  userLogin,
  userLogout,
  refreshToken,
  getUser,
  googleCallBack,
  userResetPassword
};
