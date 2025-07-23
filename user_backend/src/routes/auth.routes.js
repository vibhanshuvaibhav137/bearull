const express = require("express");
const {
    changePasswordValidation,
    loginValidation,
    registerValidation
} = require("../middlewares/validation.middleware");
const {
    changeCurrentPassword,
    loginUser,
    logoutUser,
    refreshAccessToken,
    registerUser
} = require("../controllers/auth.controller");
const { verifyJWT } = require("../middlewares/auth.middleware");

const auth = express.Router();

// @route   POST /api/v1/auth/register
// @desc    Register a new user
// @access  Public
auth.route("/register").post(registerValidation, registerUser);

// @route   POST /api/v1/auth/login
// @desc    Login user
// @access  Public
auth.route("/login").post(loginValidation, loginUser);

// @route   POST /api/v1/auth/logout
// @desc    Logout user
// @access  Private
auth.route("/logout").post(verifyJWT, logoutUser);

// @route   POST /api/v1/auth/refresh-token
// @desc    Refresh Access token
// @access  Private
auth.route("/refresh-token").post(refreshAccessToken);

// @route   POST /api/v1/auth/change-password
// @desc    Change account password
// @access  Private
auth.route("/change-password").post(verifyJWT, changePasswordValidation, changeCurrentPassword);

module.exports = auth;
