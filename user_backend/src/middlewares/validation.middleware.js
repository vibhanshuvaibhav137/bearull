const { validationResult, body, param } = require("express-validator");
const { ApiError } = require("../utils/ApiError");

const validateRequest = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return next(new ApiError(400, "Validation Error", errors.array()));
    }
    next();
};

// Pre-registration email validations
const preRegistrationEmailValidation = [
    body("email")
        .isEmail()
        .normalizeEmail()
        .withMessage("Please enter a valid email"),
    validateRequest,
];

// Pre-registration OTP validation
const preRegistrationOTPValidation = [
    body("email")
        .isEmail()
        .normalizeEmail()
        .withMessage("Please enter a valid email"),
    body("otp")
        .isLength({ min: 6, max: 6 })
        .isNumeric()
        .withMessage("OTP must be 6 digits"),
    validateRequest,
];

// Pre-registration Validation
const checkPreRegistrationValidation = [
    param("email")
        .isEmail()
        .normalizeEmail()
        .withMessage("Please provide a valid email"),
    validateRequest,
];

// Register Validation
const registerValidation = [
    body("firstName")
        .trim()
        .isLength({ min: 2, max: 25 })
        .withMessage("Name must be between 2 and 25 characters"),
    body("lastName")
        .trim()
        .isLength({ min: 2, max: 25 })
        .withMessage("Name must be between 2 and 25 characters"),
    body("email")
        .isEmail()
        .normalizeEmail()
        .withMessage("Please enter a valid email"),
    body("password")
        .isLength({ min: 6 })
        .withMessage("Password must be at least 6 characters"),
    body("mobile")
        .optional()
        .customSanitizer((value) => value.replace(/\D/g, "").replace(/^91/, ""))
        .isLength({ min: 10, max: 10 })
        .withMessage("Please enter a valid 10-digit Indian phone number"),
    validateRequest,
];

// Login Validation
const loginValidation = [
    body("email")
        .optional()
        .isEmail()
        .normalizeEmail()
        .withMessage("Please enter a valid email"),
    body("mobile")
        .optional()
        .customSanitizer((value) => value.replace(/\D/g, "").replace(/^91/, ""))
        .isLength({ min: 10, max: 10 })
        .withMessage("Please enter a valid 10-digit Indian phone number"),
    body("loginType")
        .isIn(["password", "otp"])
        .withMessage("Login type must be either 'password' or 'otp'"),
    body("password")
        .if(body("loginType").equals("password"))
        .notEmpty()
        .withMessage("Password is required for password login"),
    body("otp")
        .if(body("loginType").equals("otp"))
        .isLength({ min: 6, max: 6 })
        .isNumeric()
        .withMessage("OTP must be 6 digits"),
    validateRequest,
];

// OTP Validation
const otpValidation = [
    body("email")
        .isEmail()
        .normalizeEmail()
        .withMessage("Please enter a valid email"),
    body("otp")
        .isLength({ min: 6, max: 6 })
        .isNumeric()
        .withMessage("OTP must be 6 digits"),
    validateRequest,
];

// Send OTP Validation
const sendOTPValidation = [
    body("email")
        .optional()
        .isEmail()
        .normalizeEmail()
        .withMessage("Please enter a valid email"),
    body("mobile")
        .optional()
        .customSanitizer((value) => value.replace(/\D/g, "").replace(/^91/, ""))
        .isLength({ min: 10, max: 10 })
        .withMessage("Please enter a valid 10-digit Indian phone number"),
    body("context")
        .isIn(["register", "login"])
        .withMessage("Context must be either 'register' or 'login'"),
    validateRequest,
];

// Change Password Validation
const changePasswordValidation = [
    body("oldPassword")
        .isLength({ min: 6 })
        .withMessage("Password must be at least 6 characters"),
    body("newPassword")
        .isLength({ min: 6 })
        .withMessage("Password must be at least 6 characters"),
    validateRequest,
];

// Update profile validation
const updateProfileValidation = [
    body("firstName")
        .optional()
        .trim()
        .isLength({ min: 2, max: 25 })
        .withMessage("Name must be between 2 and 25 characters"),
    body("lastName")
        .optional()
        .trim()
        .isLength({ min: 2, max: 25 })
        .withMessage("Name must be between 2 and 25 characters"),
    body("email")
        .optional()
        .isEmail()
        .normalizeEmail()
        .withMessage("Please enter a valid email"),
    body("mobile")
        .optional()
        .customSanitizer((value) => value.replace(/\D/g, "").replace(/^91/, ""))
        .isLength({ min: 10, max: 10 })
        .withMessage("Please enter a valid 10-digit Indian phone number"),
    body("address")
        .optional()
        .trim()
        .isLength({ min: 10, max: 250 })
        .withMessage("Address must be between 10 and 250 characters"),
    validateRequest,
];

module.exports = {
    validateRequest,
    preRegistrationEmailValidation,
    preRegistrationOTPValidation,
    checkPreRegistrationValidation,
    registerValidation,
    loginValidation,
    otpValidation,
    sendOTPValidation,
    changePasswordValidation,
    updateProfileValidation,
};
