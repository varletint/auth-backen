const jwt = require("jsonwebtoken");
const User = require("../models/user");
const { ApiError, asyncHandler } = require("./errorHandler");

const authenticate = asyncHandler(async (req, res, next) => {
  let token;

  if (req.headers.authorization?.startsWith("Bearer")) {
    token = req.headers.authorization.split(" ")[1];
  }

  if (!token) {
    throw ApiError.unauthorized("Access token required");
  }

  const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

  const user = await User.findById(decoded.userId);
  if (!user) {
    throw ApiError.unauthorized("User no longer exists");
  }

  req.user = {
    id: user._id,
    username: user.username,
    role: user.role,
  };

  next();
});

module.exports = { authenticate };
