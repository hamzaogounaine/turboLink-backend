const jwt = require("jsonwebtoken");
const User = require("../Models/User");

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
  refreshToken,
  message
) => {
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true, // Recommended for security (cannot be read by JS)
    // IMPORTANT: When running on different localhost ports (HTTP),
    // you must *not* set secure: true or SameSite: 'None'.
    // Leaving SameSite unset or setting to 'Lax' is the best practice here.
    // If 'Lax' doesn't work, try removing the sameSite property completely.
    secure : process.env.NODE_ENV === 'prod' && true,
      sameSite: process.env.NODE_ENV === 'prod' ? "None" : "Lax",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  // 2. Remove sensitive fields for the JSON response
  const userResponse = user.toObject({ getters: true });
  delete userResponse.refresh_token;
  delete userResponse.password; // If not already done in the Mongoose hook

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

const checkUsernameAvailabily = async (req , res) => {
  const username = req.query.username;
  console.log(username)

  const usernameAlreadyExits = await User.findOne({username})

  if(usernameAlreadyExits) {
    res.status(409).json('Username already exists')
  }

  res.status(200).json('Username not exists')
}

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

module.exports = {generateTokens , sendAuthResponse , handleErrors , checkUsernameAvailabily , refreshToken}
