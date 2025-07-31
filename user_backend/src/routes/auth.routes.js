const express = require("express");
const {
    changePasswordValidation,
    loginValidation,
    registerValidation,
    otpValidation,
    sendOTPValidation,
    preRegistrationEmailValidation,
    preRegistrationOTPValidation,
    checkPreRegistrationValidation
} = require("../middlewares/validation.middleware");
const {
    changeCurrentPassword,
    loginUser,
    logoutUser,
    refreshAccessToken,
    registerUser,
    verifyEmailOTP,
    resendOTP,
    sendLoginOTP,
    sendPreRegistrationOTP,
    verifyPreRegistrationOTP,
    checkPreRegistrationStatus
} = require("../controllers/auth.controller");
const { verifyJWT } = require("../middlewares/auth.middleware");

const auth = express.Router();

// @route   POST /api/v1/auth/send-pre-registration-otp
// @desc    Send OTP for pre-registration email verification
// @access  Public
auth.route("/send-pre-registration-otp").post(preRegistrationEmailValidation, sendPreRegistrationOTP);

// @route   POST /api/v1/auth/verify-pre-registration-otp
// @desc    Verify pre-registration email OTP
// @access  Public
auth.route("/verify-pre-registration-otp").post(preRegistrationOTPValidation, verifyPreRegistrationOTP);

// @route   GET /api/v1/auth/check-pre-registration/:email
// @desc    Check pre-registration verification status
// @access  Public
auth.route("/check-pre-registration/:email").get(checkPreRegistrationValidation, checkPreRegistrationStatus);

// @route   POST /api/v1/auth/register
// @desc    Register a new user (requires pre-verified email)
// @access  Public
auth.route("/register").post(registerValidation, registerUser);

// @route   POST /api/v1/auth/verify-email
// @desc    Verify email with OTP (backward compatibility)
// @access  Public
auth.route("/verify-email").post(otpValidation, verifyEmailOTP);

// @route   POST /api/v1/auth/resend-otp
// @desc    Resend email OTP (works for both registration and login)
// @access  Public
auth.route("/resend-otp").post(sendOTPValidation, resendOTP);

// @route   POST /api/v1/auth/send-login-otp
// @desc    Send OTP for login
// @access  Public
auth.route("/send-login-otp").post(sendOTPValidation, sendLoginOTP);

// @route   POST /api/v1/auth/login
// @desc    Login user (password or OTP)
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