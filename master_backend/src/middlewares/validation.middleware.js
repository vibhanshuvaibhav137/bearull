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
    body("name")
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage("Name must be between 2 and 50 characters"),
    body("email")
        .isEmail()
        .normalizeEmail()
        .withMessage("Please enter a valid email"),
    body("password")
        .isLength({ min: 6 })
        .withMessage("Password must be at least 6 characters"),
    body("phone")
        .isMobilePhone("en-IN")
        .withMessage("Please enter a valid phone number"),
    validateRequest,
];

const loginValidation = [
    body("email")
        .isEmail()
        .normalizeEmail()
        .withMessage("Please enter a valid email"),
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
    body("name")
        .optional()
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage("Name must be between 2 and 50 characters"),
    body("phone")
        .optional()
        .isMobilePhone("en-IN")
        .withMessage("Please enter a valid phone number"),
    validateRequest,
];

const addMoneyValidation = [
    body("amount")
        .isNumeric()
        .isFloat({ min: 1, max: 100000 })
        .withMessage("Amount must be between 1 and 100000"),
    validateRequest,
];

module.exports = {
    validateRequest,
    registerValidation,
    loginValidation,
    changePasswordValidation,
    updateProfileValidation,
    addMoneyValidation,
};
