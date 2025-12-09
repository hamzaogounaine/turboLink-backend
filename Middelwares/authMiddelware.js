const jwt = require('jsonwebtoken');

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;

const authMiddelware = async (req , res , next) => {
const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Access token not provided' });
  }
  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, payload) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid or expired access token' });
    }
    // Attach the user ID to the request object for use in subsequent handlers
    req.user = payload;
    next();
  });
}

module.exports = authMiddelware;