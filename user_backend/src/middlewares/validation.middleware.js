const { validationResult, body } = require("express-validator");
const { ApiError } = require("../utils/ApiError");

const validateRequest = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return next(new ApiError(401, "Validation Error", errors.array()));
    }
    next();
};

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
    body("phone")
        .optional()
        .customSanitizer((value) => value.replace(/\D/g, "").replace(/^91/, ""))
        .isLength({ min: 10, max: 10 })
        .withMessage("Please enter a valid 10-digit Indian phone number"),
];

const loginValidation = [
    body("email")
    .optional()
        .isEmail()
        .normalizeEmail()
        .withMessage("Please enter a valid email"),
    body("phone")
        .optional()
        .customSanitizer((value) => value.replace(/\D/g, "").replace(/^91/, ""))
        .isLength({ min: 10, max: 10 })
        .withMessage("Please enter a valid 10-digit Indian phone number"),
    body("password").notEmpty().withMessage("Password is required"),
    validateRequest,
];

const changePasswordValidation = [
    body("oldPassword")
        .isLength({ min: 6 })
        .withMessage("Password must be at least 6 characters"),
    body("newPassword")
        .isLength({ min: 6 })
        .withMessage("Password must be at least 6 characters"),
    validateRequest,
];

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
    body("phone")
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
    registerValidation,
    loginValidation,
    changePasswordValidation,
    updateProfileValidation,
};
