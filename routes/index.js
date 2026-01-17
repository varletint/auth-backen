const express = require("express");
const router = express.Router();

const authroutes = require("./authroutes");

router.use("/auth", authroutes);

module.exports = router;
