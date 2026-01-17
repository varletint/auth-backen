const User = require("../models/user");
const { ApiError, asyncHandler } = require("../middleware/errorHandler");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const generateToken = (userId) => {
  const refreshToken = jwt.sign({ userId }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: "7d",
  });

  const accessToken = jwt.sign({ userId }, process.env.JWT_ACCESS_SECRET, {
    expiresIn: "15m",
  });

  return { accessToken, refreshToken };
};

const register = asyncHandler(async (req, res) => {
  const { username, password, role } = req.body;
  const sanitizedUsername = username?.trim().toLowerCase();

  if (!sanitizedUsername || !password) {
    throw ApiError.badRequest("Username and password are required");
  }

  const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
  if (!usernameRegex.test(sanitizedUsername)) {
    throw ApiError.badRequest(
      "Username must be 3-30 characters and can only contain letters, numbers, and underscores"
    );
  }

  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
  if (!passwordRegex.test(password)) {
    throw ApiError.badRequest(
      "Password must be at least 8 characters with 1 uppercase, 1 lowercase, and 1 number"
    );
  }

  const existingUser = await User.findOne({ username: sanitizedUsername });
  if (existingUser) {
    throw ApiError.conflict("Username already taken");
  }

  const hashedSalt = await bcrypt.genSalt(10);

  const hashedPassword = await bcrypt.hash(password, hashedSalt);

  const user = await User.create({
    username: sanitizedUsername,
    password: hashedPassword,
    role: role || "user",
  });

  const { accessToken, refreshToken } = generateToken(user._id);

  await User.findByIdAndUpdate(user._id, { refreshToken });

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/",
    domain: "localhost",
  });

  res.status(201).json({
    success: true,
    message: "User registered successfully",
    data: {
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
      },
      accessToken,
    },
  });
});

const login = asyncHandler(async (req, res) => {
  const { username, password } = req.body;
  console.log(`Login attempt for: ${username}`);
  const sanitizedUsername = username?.trim().toLowerCase();

  if (!sanitizedUsername || !password) {
    throw ApiError.badRequest("Username and password are required");
  }

  const user = await User.findOne({ username: sanitizedUsername }).select(
    "+password"
  );
  if (!user) throw ApiError.notFound("User not found");

  const validPassword = await user.comparePassword(password);
  if (!validPassword) throw ApiError.unauthorized("Invalid credentials");

  const { accessToken, refreshToken } = generateToken(user._id);

  await User.findByIdAndUpdate(user._id, { refreshToken });

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/",
  });

  res.status(200).json({
    success: true,
    message: "User logged in successfully",
    data: {
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
      },
      accessToken,
    },
  });
});

const refresh = asyncHandler(async (req, res) => {
  const { refreshToken } = req.cookies;
  console.log("Refresh Request Cookies:", req.cookies);
  console.log("NODE_ENV:", process.env.NODE_ENV);

  if (!refreshToken) {
    throw ApiError.unauthorized("Refresh token not found");
  }

  let decoded;
  try {
    decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
  } catch (error) {
    throw ApiError.unauthorized("Invalid or expired refresh token");
  }

  const user = await User.findById(decoded.userId).select("+refreshToken");
  if (!user || user.refreshToken !== refreshToken) {
    throw ApiError.unauthorized("Invalid refresh token");
  }

  const accessToken = jwt.sign(
    { userId: user._id },
    process.env.JWT_ACCESS_SECRET,
    {
      expiresIn: "15m",
    }
  );

  // Generate new refresh token (rotation)
  const newRefreshToken = jwt.sign(
    { userId: user._id },
    process.env.JWT_REFRESH_SECRET,
    {
      expiresIn: "7d",
    }
  );

  // Save new refresh token to DB (invalidates old one)
  await User.findByIdAndUpdate(user._id, { refreshToken: newRefreshToken });

  // Send new refresh token as cookie
  res.cookie("refreshToken", newRefreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: "/",
  });

  res.status(200).json({
    success: true,
    message: "Token refreshed successfully",
    data: { accessToken },
  });
});

const getMe = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.id);

  res.status(200).json({
    success: true,
    message: "User fetched successfully",
    user: {
      id: user._id,
      username: user.username,
      role: user.role,
    },
  });
});

const logout = asyncHandler(async (req, res) => {
  const { refreshToken } = req.cookies;

  if (refreshToken) {
    await User.findOneAndUpdate({ refreshToken }, { refreshToken: null });
  }

  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });

  res.status(200).json({
    success: true,
    message: "Logged out successfully",
  });
});

module.exports = { register, login, refresh, logout, getMe };
