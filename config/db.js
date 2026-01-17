/*const crypto = require("crypto");

const generateSalt = () => {
  return crypto.randomBytes(16).toString("hex");
};

const generateHash = (password, salt) => {
  return crypto
    .pbkdf2Sync(password, salt, 100000, 64, "sha512")
    .toString("hex");
};

const decodeHash = (hash) => {
  return crypto
    .pbkdf2Sync(hash, generateSalt(), 100000, 64, "sha512")
    .toString("hex");
};


module.exports = {
  generateSalt,
  generateHash,
};
*/

const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URL);
    console.log("MongoDB connected");
  } catch (error) {
    console.error("MongoDB connection error:", error);
    process.exit(1);
  }
};

module.exports = connectDB;
