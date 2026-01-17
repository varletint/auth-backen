const express = require("express");
const router = express.Router();
const { authenticate } = require("../middleware/authen");

const {
  register,
  login,
  refresh,
  logout,
  getMe,
} = require("../controllers/auth");

router.post("/register", register);
router.post("/login", login);
router.post("/refresh", refresh);
router.post("/logout", authenticate, logout);
router.get("/me", authenticate, getMe);

module.exports = router;
