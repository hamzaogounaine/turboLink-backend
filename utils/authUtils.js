const jwt = require("jsonwebtoken");
const User = require("../Models/User");
const crypto = require("crypto");
const { sendVerificationLink } = require("./sendEmails");
const getAccountVerificationEmailTemplate = require("../emails/emailVerficationTemplates");
const sharp = require("sharp");
const { uploadToS3 } = require("../lib/s3-upload");

const generateTokens = (user) => {
  const accessToken = jwt.sign(
    { userId: user._id },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "16m" }
  );

  const refreshToken = jwt.sign(
    { userId: user._id },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: "7d" }
  );

  return { accessToken, refreshToken };
};

const sendAuthResponse = async (
  res,
  user,
  accessToken,
  refreshToken = null,
  message = null
) => {
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true, // Recommended for security (cannot be read by JS)
    // IMPORTANT: When running on different localhost ports (HTTP),
    // you must *not* set secure: true or SameSite: 'None'.
    // Leaving SameSite unset or setting to 'Lax' is the best practice here.
    // If 'Lax' doesn't work, try removing the sameSite property completely.
    secure: process.env.NODE_ENV === "prod" && true,
    sameSite: process.env.NODE_ENV === "prod" ? "None" : "Lax",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  // 2. Remove sensitive fields for the JSON response
  const userResponse = user.toObject({ getters: true });
  delete userResponse.refresh_token;
  delete userResponse.last_login_ip;

  return res.status(200).json({ user: userResponse, accessToken, message });
};

const handleErrors = (err) => {
  const errors = { username: "", password: "", email: "" };

  if (err.name === "ValidationError") {
    for (const field in err.errors) {
      if (errors.hasOwnProperty(field)) {
        errors[field] = err.errors[field].message;
      }
    }
  }
  // Error handling for unique validation
  if (err.code === 11000) {
    const fieldMatch = err.message.match(/index: (.*?)_1/);
    const field = fieldMatch ? fieldMatch[1] : null;

    if (field) {
      errors[field] = `${field}Unique`;
    }
  }

  return errors;
};

const generateEmailVeficationToken = (userId) => {
  const jsonSecret = process.env.EMAIL_VERIFICATION_TOKEN_SECRET;

  const payload = {
    userId,
    type: "email_verification",
  };

  const token = jwt.sign(payload, jsonSecret, { expiresIn: "15m" });

  return token;
};

const resendEmailVerificationLink = async (req, res) => {
  const { userId } = req.body;
  const lang = req.cookies["NEXT_LOCALE"];

  const user = await User.findById(userId);

  if (!user) {
    return res.status(404).json({ message: "noUserFound" });
  }

  if (user.is_email_verified) {
    return res.status(404).json({ message: "emailAlreadyVerified" });
  }

  const verificationToken = generateEmailVeficationToken(userId);
  const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;

  const { html, subject } = getAccountVerificationEmailTemplate(
    lang,
    user.username,
    verificationLink
  );

  const emailSent = await sendVerificationLink(user.email, subject, html);

  if (!emailSent) {
    return res
      .status(400)
      .json({ message: "Error while sending verification link" });
  }

  return res.status(200).json({ message: "Email has been sent successfully" });
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

const verifyDevice = async (req, res) => {
  const { code, email } = req.body;
  const clientIP = req.ip;

  if (!code) {
    return res.status(403).json({ message: "noCodeProvided" });
  }

  const user = await User.findOne({ email });

  if (!user) {
    return res.status(404).json({ message: "noUserFound" });
  }

  if (user.ip_verification_code !== code) {
    return res.status(403).json({ message: "invalidCode" });
  }

  if (user.ip_verification_code_expiration < Date.now()) {
    return res.status(403).json({ message: "codeExpired" });
  }

  const { accessToken, refreshToken } = generateTokens(user);

  const updatdUser = await User.findByIdAndUpdate(user._id, {
    ip_verification_code: null,
    ip_verification_code_expiration: null,
    refresh_token: refreshToken,
    last_login_ip: clientIP,
  });

  console.log(updatdUser);

  return sendAuthResponse(
    res,
    updatdUser,
    accessToken,
    refreshToken,
    (message = "deviceVerified")
  );
};

const editAvatar = async (req, res) => {
  if (!req.file || !req.file.buffer) {
    return res.status(400).json({ 
      message: "No image file provided or file buffer is empty." 
    });
  }

  if (!req.file.mimetype.startsWith('image')) {
    return res.status(400).json({ 
        message: "Invalid file type. Only images are allowed." 
    });
  }

  try {
    // 💥 FIX: Correctly access the file buffer from multer (req.file.buffer)
    const resizedBuffer = await sharp(req.file.buffer) 
      .resize({ width: 500, height: 500, fit: "cover" })
      .toFormat("jpeg", { mozjpeg: true, quality: 80 }) 
      .toBuffer();

    const fileName = `avatars/${crypto.randomUUID()}.jpeg`;
    
    // Upload the resized buffer to S3
    const imageUrl = await uploadToS3(resizedBuffer, fileName, 'image/jpeg');

    // SUCCESS: Return the S3 URL
    return res.status(200).json({ url: imageUrl });
    
  } catch (err) {
    // 💥 FIX: Proper Error Handling. Do not just log and hang the request.
    console.error('Avatar Processing/S3 Upload Error:', err);
    
    // Return a 500 error response to the client
    return res.status(500).json({ 
      message: "Image processing or upload failed on the server." 
    });
  }
};

const updateAvatarUrl = async (req , res) => {
  const {avatar , userId} = req.body;

  if(!avatar) {
    return res.status(400).json({message : "Provice a valide url"})
  }

  if(!userId) {
    return res.status(400).json({message: "Provide a user Id"})
  }

  const updatedUser = await User.findByIdAndUpdate(userId , {avatar_url : avatar})

  if(updatedUser) {
    return res.status(200).json({message : 'avatarUpdated'})
  }
} 

// module.exports = editAvatar;

module.exports = {
  generateTokens,
  sendAuthResponse,
  handleErrors,
  resendEmailVerificationLink,
  generateEmailVeficationToken,
  refreshToken,
  verifyDevice,
  editAvatar,
  updateAvatarUrl
};
