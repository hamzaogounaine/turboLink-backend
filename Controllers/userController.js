const User = require("../Models/User");
const jwt = require("jsonwebtoken");

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

const sendAuthResponse = async (res, user, accessToken, refreshToken) => {
  res.cookie("refreshToken", refreshToken, {
   httpOnly: true, // Recommended for security (cannot be read by JS)
    // IMPORTANT: When running on different localhost ports (HTTP),
    // you must *not* set secure: true or SameSite: 'None'.
    // Leaving SameSite unset or setting to 'Lax' is the best practice here.
    // If 'Lax' doesn't work, try removing the sameSite property completely.
    sameSite: 'Lax', 
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  // 2. Remove sensitive fields for the JSON response
  const userResponse = user.toObject({ getters: true });
  delete userResponse.refresh_token;
  delete userResponse.password; // If not already done in the Mongoose hook

  return res.status(200).json({ user: userResponse, accessToken });
};

// Add this function to your file:

const getUser = async (req, res) => {
  const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
  
  // 1. Check for the Authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: "Access token missing or invalid format" });
  }

  // 2. Extract the token
  const accessToken = authHeader.split(' ')[1];

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
    console.error('Access token verification failed:', err.message);
    
    // An expired access token should result in a 401 status, 
    // which prompts the front-end (via your Axios interceptor) to try refreshing.
    return res.status(401).json({ error: "Access token expired or invalid" });
  }
};

const userSignUp = async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const existingUser = await User.findOne({
      $or: [{ email: email }, { username: username }],
    });

    const createdUser = await User.create({ email, username, password });

    const { accessToken, refreshToken } = generateTokens(createdUser);

    const updatedUser = await User.findByIdAndUpdate(
      createdUser._id,
      { refresh_token: refreshToken },
      { new: true } // returns the updated document
    );

    return sendAuthResponse(res, updatedUser, accessToken, refreshToken);
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

    return sendAuthResponse(res, updatedUser, accessToken, refreshToken);
  } catch (err) {
    if (err.message === "invalidCredentials") {
      return res.status(403).json(err.message);
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
    console.error('Refresh token error:', err);
    return res.status(403).json({ error: "Invalid or expired refresh token" });
  }
};

module.exports = {
  userSignUp,
  userLogin,
  refreshToken,
  getUser
};
