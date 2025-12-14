const User = require("../Models/User");
const jwt = require("jsonwebtoken");
const {
  generateTokens,
  sendAuthResponse,
  handleErrors,
  generateEmailVeficationToken,
  cleanUser,
} = require("../utils/authUtils");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const { sendVerificationLink } = require("../utils/sendEmails");
const getVerificationEmailTemplate = require("../emails/deviceVerificationTemplates");
const getAccountVerificationEmailTemplate = require("../emails/emailVerficationTemplates");
const { OAuth2Client } = require("google-auth-library");
const rateLimit = require("express-rate-limit");
const redis = require("../lib/Redis");

const getUser = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "tokenMissingOrInvalid" });
  }

  const accessToken = authHeader.split(" ")[1];

  try {
    const payload = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);

    const user = await User.findById(payload.userId)
      .select("-password -refresh_token -ip_verification_code -last_login_ip")
      .lean();

    if (!user) {
      return res.status(404).json({ error: "userNotFound" });
    }

    return res.status(200).json({ user });
  } catch (err) {
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "tokenInvalid" });
    }
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ error: "tokenExpired" });
    }
    return res.status(401).json({ error: "tokenExpiredOrInvalid" });
  }
};

const userSignUp = async (req, res) => {
  const { username, email, password, firstName, lastName } = req.body;
  const lang = req.cookies["NEXT_LOCALE"];

  try {
    // Check for existing users - use separate queries to prevent timing attacks
    const emailExists = await User.exists({ email });
    const usernameExists = await User.exists({ username });

    if (emailExists || usernameExists) {
      const errors = {};
      if (emailExists) errors.email = "emailTaken";
      if (usernameExists) errors.username = "usernameTaken";

      // Add small delay to prevent timing-based enumeration
      await new Promise((resolve) => setTimeout(resolve, 100));
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
      { new: true }
    ).select("-password -refresh_token");

    const verificationToken = crypto.randomBytes(32).toString("hex");
    const tokenExpiration = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

    await User.findByIdAndUpdate(createdUser._id, {
      email_verification_token: verificationToken,
      email_verification_token_expiration: tokenExpiration,
    });

    const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;
    const { html, subject } = getAccountVerificationEmailTemplate(
      lang,
      createdUser.username,
      verificationLink
    );

    sendVerificationLink(createdUser.email, subject, html).catch((err) => {
      console.error("Email delivery failed:", err.message);
    });

    return sendAuthResponse(
      res,
      cleanUser(updatedUser),
      accessToken,
      refreshToken,
      "accountCreated"
    );
  } catch (err) {
    console.error("Signup Error:", err.message);
    return res.status(500).json({ message: "serverError" });
  }
};

const userLogin = async (req, res) => {
  const { email, password } = req.body;
  const clientIP = req.headers["x-forwarded-for"]
    ? req.headers["x-forwarded-for"].split(",")[0].trim()
    : req.socket.remoteAddress;
  const lang = req.cookies["NEXT_LOCALE"];
  const lockKey = `account_lock:${email}`;
  const attemptsKey = `login_attempts:${email}`;

  try {
    const isLocked = await redis.get(lockKey);
    if (isLocked) {
      const ttl = await redis.ttl(lockKey);
      const minutesRemaining = Math.ceil(ttl / 60);
      return res.status(403).json({
        message: "accountLocked",
        minutesRemaining,
      });
    }

    const user = await User.findOne({ email }).select("+password");
    console.log('userIp' , clientIP , 'dbIp' , user.last_login_ip)

    if (!user) {
      // Add delay to prevent timing attacks
      await new Promise((resolve) => setTimeout(resolve, 100));
      return res.status(403).json({ message: "invalidCredentials" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      const attempts = await redis.incr(attemptsKey);

      // Lock account after 5 failed attempts
      if (attempts === 1) {
        await redis.expire(attemptsKey, 15 * 60);
      }

      // Lock account after 5 failed attempts
      if (attempts >= 5) {
        await redis.setex(lockKey, 10 * 60, "locked"); // 30 min lock
        await redis.del(attemptsKey); // Clear attempts counter

        return res.status(403).json({
          message: "accountLockedDueToFailedAttempts",
          minutesRemaining: 30,
        });
      }

      await user.save();

      // Add delay to prevent timing attacks
      await new Promise((resolve) => setTimeout(resolve, 100));
      return res.status(403).json({
        message: "invalidCredentials",
        attemptsRemaining: 5 - attempts,
      });
    }

    // Reset failed attempts on successful login
    await redis.del(attemptsKey);
    await redis.del(lockKey);

    // IP Verification with stronger token
    if (user.last_login_ip && user.last_login_ip !== clientIP) {
      const code = crypto.randomBytes(32).toString("hex");
      const codeExpiration = Date.now() + 15 * 60 * 1000;

      await User.findByIdAndUpdate(user._id, {
        ip_verification_token: code,
        ip_verification_token_expiration: codeExpiration,
        pending_login_ip: clientIP,
      });

      // For user display, create a shorter code
      const displayCode = crypto.randomInt(100000, 999999);

      const { html, subject } = getVerificationEmailTemplate(
        lang,
        user.username,
        clientIP,
        displayCode
      );

      await sendVerificationLink(user.email, subject, html);

      // Store the display code mapping (you'll need to add this field to schema)
      await User.findByIdAndUpdate(user._id, {
        ip_verification_display_code: displayCode,
      });

      return res.status(200).json({
        message: "mustVerifyIp",
        codeSent: true,
      });
    }

    const { accessToken, refreshToken } = generateTokens(user);

    const updatedUser = await User.findByIdAndUpdate(
      user._id,
      {
        refresh_token: refreshToken,
        last_login_ip: clientIP,
      },
      { new: true }
    ).select("-password -refresh_token");

    return sendAuthResponse(
      res,
      cleanUser(updatedUser),
      accessToken,
      refreshToken,
      "loginSuccess"
    );
  } catch (err) {
    console.error("Login error:", err.message);
    return res.status(500).json({ message: "serverError" });
  }
};

const verifyIpCode = async (req, res) => {
  const { email, code } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "userNotFound" });
    }

    // Check if code is expired
    if (
      !user.ip_verification_token_expiration ||
      user.ip_verification_token_expiration < Date.now()
    ) {
      return res.status(400).json({ message: "codeExpired" });
    }

    // Verify the display code
    if (user.ip_verification_display_code !== parseInt(code)) {
      return res.status(403).json({ message: "invalidCode" });
    }

    const clientIP = user.pending_login_ip || req.ip;

    const { accessToken, refreshToken } = generateTokens(user);

    const updatedUser = await User.findByIdAndUpdate(
      user._id,
      {
        refresh_token: refreshToken,
        last_login_ip: clientIP,
        ip_verification_token: null,
        ip_verification_token_expiration: null,
        ip_verification_display_code: null,
      },
      { new: true }
    ).select("-password -refresh_token");

    return sendAuthResponse(
      res,
      updatedUser,
      accessToken,
      refreshToken,
      "loginSuccess"
    );
  } catch (err) {
    console.error("IP verification error:", err.message);
    return res.status(500).json({ message: "serverError" });
  }
};

const userLogout = async (req, res) => {
  const authHeader = req.headers.authorization;

  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "prod",
    sameSite: process.env.NODE_ENV === "prod" ? "None" : "Lax",
  });

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(200).json({ message: "loggedOut" });
  }

  const accessToken = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);

    await User.findByIdAndUpdate(decoded.userId, { refresh_token: null });
    return res.status(200).json({ message: "loggedOut" });
  } catch (err) {
    // Even if token is invalid, clear the cookie and return success
    return res.status(200).json({ message: "loggedOut" });
  }
};

const userResetPassword = async (req, res) => {
  const { oldPassword, newPassword, newConfirmationPassword } = req.body;
  const authHeader = req.headers.authorization;
  const accessToken = authHeader && authHeader.split(" ")[1];

  if (!accessToken) return res.status(401).json({ message: "tokenMissing" });

  if (newPassword !== newConfirmationPassword) {
    return res.status(400).json({ message: "passwordsDontMatch" });
  }

  // Password strength validation (add to Zod schema ideally)
  if (newPassword.length < 6) {
    return res.status(400).json({ message: "passwordTooShort" });
  }

  try {
    const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
    const user = await User.findById(decoded.userId).select("+password");

    if (!user) return res.status(404).json({ message: "userNotFound" });
    if (user.is_google_user)
      return res.status(403).json({ message: "actionNotAllowedForGoogleUser" });

    const isPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isPasswordValid)
      return res.status(401).json({ message: "currentPasswordIncorrect" });

    // Ensure new password is different from old
    if (await bcrypt.compare(newPassword, user.password)) {
      return res.status(400).json({ message: "newPasswordMustBeDifferent" });
    }

    user.password = newPassword;
    user.refresh_token = null;

    // Invalidate all sessions by updating a session version (add this field to schema)

    await user.save();
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "prod",
      sameSite: process.env.NODE_ENV === "prod" ? "None" : "Lax",
    });

    return res.status(200).json({ message: "passwordResetSuccess" });
  } catch (err) {
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ message: "tokenInvalid" });
    }
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ message: "tokenExpired" });
    }
    console.error("Reset password error:", err.message);
    return res.status(401).json({ message: "tokenExpiredOrInvalid" });
  }
};

const updateProfile = async (req, res) => {
  const { userId, firstName, lastName, email, phoneNumber, password } =
    req.body;
  const lang = req.cookies["NEXT_LOCALE"];

  if (!userId || !password)
    return res.status(400).json({ message: "missingCredentials" });

  try {
    const user = await User.findById(userId).select("+password");

    if (!user) return res.status(404).json({ message: "userNotFound" });
    if (user.is_google_user)
      return res.status(403).json({ message: "googleProfileUpdateNotAllowed" });

    const pwdIsValid = await bcrypt.compare(password, user.password);
    if (!pwdIsValid) {
      // Add delay to prevent timing attacks
      await new Promise((resolve) => setTimeout(resolve, 100));
      return res.status(403).json({ message: "incorrectPassword" });
    }

    // Validate phone number format if provided
    if (
      phoneNumber &&
      !/^\+?[1-9]\d{1,14}$/.test(phoneNumber.replace(/[\s\-()]/g, ""))
    ) {
      return res.status(400).json({ message: "invalidPhoneNumber" });
    }

    if (firstName) user.first_name = firstName;
    if (lastName) user.last_name = lastName;
    if (phoneNumber) user.phone_number = phoneNumber;

    let successKey = "profileUpdated";

    if (email && email !== user.email) {
      // Validate email format
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({ message: "invalidEmail" });
      }

      const emailExists = await User.exists({ email });
      if (emailExists) {
        await new Promise((resolve) => setTimeout(resolve, 100));
        return res.status(400).json({ message: "emailTaken" });
      }

      // user.new_email_pending = email;

      // Generate secure verification token
      const verificationToken = crypto.randomBytes(32).toString("hex");
      const tokenExpiration = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

      // user.email_update_verification_token = verificationToken;
      // user.email_update_verification_token_expiration = tokenExpiration;

      const verificationLink = `${process.env.FRONTEND_URL}/verify-update-email?token=${verificationToken}`;

      const { html, subject } = getAccountVerificationEmailTemplate(
        lang,
        user.username || user.first_name,
        verificationLink
      );

      sendVerificationLink(email, subject, html).catch((e) => {
        console.error("Email delivery failed:", e.message);
      });

      successKey = "profileUpdatedCheckEmail";
    }

    const updatedUser = await user.save();

    return res.status(200).json({
      message: successKey,
      user: cleanUser(updatedUser),
    });
  } catch (err) {
    console.error("Profile update error:", err.message);
    return res.status(500).json({ message: "serverError" });
  }
};

const updateGoogleUsersProfile = async (req, res) => {
  const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
  const { userId, firstName, lastName, phoneNumber, accessToken } = req.body;

  if (!userId || !accessToken)
    return res.status(400).json({ message: "missingFields" });

  try {
    // Verify Google token
    // const ticket = await client.verifyIdToken({
    //   idToken: accessToken,
    //   audience: process.env.GOOGLE_CLIENT_ID,
    // });

    const payload = await client.getTokenInfo(accessToken);
    console.log(payload);
    if (!payload || !payload.sub) {
      return res.status(403).json({ message: "invalidGoogleToken" });
    }

    // Validate phone number format if provided
    if (
      phoneNumber &&
      !/^\+?[1-9]\d{1,14}$/.test(phoneNumber.replace(/[\s\-()]/g, ""))
    ) {
      return res.status(400).json({ message: "invalidPhoneNumber" });
    }

    const updatedUser = await User.findOneAndUpdate(
      { _id: userId, googleId: payload.sub },
      {
        $set: {
          ...(firstName && { first_name: firstName }),
          ...(lastName && { last_name: lastName }),
          ...(phoneNumber && { phone_number: phoneNumber }),
        },
      },
      { new: true, runValidators: true }
    ).select("-password -refresh_token");

    if (!updatedUser) {
      return res
        .status(404)
        .json({ message: "userNotFoundOrVerificationFailed" });
    }

    return res.status(200).json({
      message: "profileUpdated",
      user: cleanUser(updatedUser),
    });
  } catch (err) {
    console.log(err);
    console.error("Google Profile Update Error:", err.message);

    if (err.message && err.message.includes("Token")) {
      return res.status(403).json({ message: "invalidGoogleToken" });
    }

    return res.status(500).json({ message: "serverError" });
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
// Export rate limiters so they can be applied in routes
module.exports = {
  getUser,
  userSignUp,
  userLogin,
  verifyIpCode,
  userLogout,
  userResetPassword,
  updateProfile,
  updateGoogleUsersProfile,
  googleCallBack,
};
