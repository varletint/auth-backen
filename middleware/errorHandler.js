class ApiError extends Error {
  constructor(message, statusCode, details = null) {
    super(message);
    this.statusCode = statusCode;
    this.details = details;
    this.name = "ApiError";
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }

  static badRequest(message, details = null) {
    return new ApiError(message, 400, details);
  }

  static unauthorized(message, details = null) {
    return new ApiError(message, 401, details);
  }

  static forbidden(message, details = null) {
    return new ApiError(message, 403, details);
  }

  static notFound(message, details = null) {
    return new ApiError(message, 404, details);
  }

  static conflict(message, details = null) {
    return new ApiError(message, 409, details);
  }

  static internal(message, details = null) {
    return new ApiError(message, 500, details);
  }
}

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch((error) => next(error));
};

const errorHandler = (err, req, res, next) => {
  let statusCode = err.statusCode || 500;
  let message = err.message || "Internal Server Error";
  let details = err.details || null;

  console.error(`[${new Date().toISOString()}] Error: `, {
    name: err.name,
    message: err.message,
    stack: err.stack,
    details: err.details,
    method: req.method,
    url: req.url,
    params: req.params,
    query: req.query,
    body: req.body,
    user: req.user,
  });

  if (err.name === "CastError") {
    statusCode = 400;
    message = `Invalid ${err.path}: ${err.value}`;
  }
  if (err.code === 11000) {
    statusCode = 409;
    const field = Object.keys(err.keyValue)[0];
    message = `Duplicate ${field}`;
    details = { field, value: err.keyValue[field] };
  }
  if (err.name === "TokenExpiredError") {
    statusCode = 401;
    message = "Token expired";
    details = { message: err.message };
  }
  if (err.name === "JsonWebTokenError") {
    statusCode = 401;
    message = "Invalid token";
    details = { message: err.message };
  }

  const response = {
    status: statusCode,
    message,
    ...(details && { details }),
    ...(process.NODE_ENV === "development" && {
      stack: err.stack,
      error: err.name,
    }),
  };
  console.log(response);
  return res.status(statusCode).json(response);
};

const notFoundHandler = (req, res, next) => {
  res.status(404).json({
    success: false,
    status: 404,
    message: "url not found",
    details: null,
    method: req.method,
    url: req.url,
    params: req.params,
    query: req.query,
    body: req.body,
    user: req.user,
  });
};

module.exports = {
  ApiError,
  asyncHandler,
  errorHandler,
  notFoundHandler,
};
