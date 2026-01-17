const crypto = require("crypto");
const { ApiError } = require("./errorHandler");

const generateCsrfToken = () => {
  return crypto.randomBytes(32).toString("hex");
};

const setCsrfToken = (req, res, next) => {
  if (!req.cookies.csrfToken) {
    const token = generateCsrfToken();
    res.cookie("csrfToken", token, {
      httpOnly: false, // Must be readable by JavaScript
      secure: process.env.NODE_ENV === "production",
      sameSite: "Lax",
      maxAge: 24 * 60 * 60 * 1000,
      path: "/",
    });
  }
  next();
};

// Middleware to validate CSRF token on state-changing requests
const validateCsrfToken = (req, res, next) => {
  const safeMethods = ["GET", "HEAD", "OPTIONS"];
  if (safeMethods.includes(req.method)) {
    return next();
  }

  const cookieToken = req.cookies.csrfToken;
  const headerToken = req.headers["x-csrf-token"];

  if (!cookieToken || !headerToken) {
    throw ApiError.forbidden("CSRF token missing");
  }

  if (cookieToken !== headerToken) {
    throw ApiError.forbidden("CSRF token mismatch");
  }

  next();
};

module.exports = { generateCsrfToken, setCsrfToken, validateCsrfToken };
