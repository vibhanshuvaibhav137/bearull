const express = require("express");
const { verifyJWT } = require("../middlewares/auth.middleware");
const { getProfile, updateProfile } = require("../controllers/user.controller");
const { updateProfileValidation } = require("../middlewares/validation.middleware");

const user = express.Router();

// @route   GET /api/v1/user/profile
// @desc    Get user profile
// @access  Private
user.route("/profile").get(verifyJWT, getProfile);

// @route   PUT /api/v1/user/profile
// @desc    Update user profile
// @access  Private
user.route("/profile").put(verifyJWT, updateProfileValidation, updateProfile);

module.exports = user;
