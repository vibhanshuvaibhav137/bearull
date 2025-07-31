const { asyncHandler } = require("../utils/asyncHandler");
const { ApiError } = require("../utils/ApiError");
const { User } = require("../models/user.model");
const { ApiResponse } = require("../utils/ApiResponse");
const { EmailService } = require("../utils/emailService");
const { OTPService } = require("../utils/otpService");
const jwt = require("jsonwebtoken");

// Generate Access And Refresh Tokens
const generateAccessAndRefreshTokens = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });

        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(
            500,
            "Something went wrong while generating refresh and access token"
        );
    }
};

// Generate Player Id
const generatePlayerId = () => {
    const chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const id = Array.from(
        { length: 8 },
        () => chars[Math.floor(Math.random() * chars.length)]
    ).join("");
    return `${id}-BEARULL`;
};

// Send Pre-registration Email Verification
const sendPreRegistrationOTP = asyncHandler(async (req, res) => {
    const { email } = req.body;

    if (!email) {
        throw new ApiError(400, "Email is required");
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
        throw new ApiError(409, "User with this email already exists");
    }

    const otp = EmailService.generateOTP();
    const otpExpiry = OTPService.createOTPExpiry();

    // Store in temporary verification storage (We can use Redis for production)
    const verificationData = {
        email,
        otp,
        otpExpiry,
        isVerified: false,
        createdAt: new Date(),
    };

    global.preRegistrationCache = global.preRegistrationCache || new Map();
    global.preRegistrationCache.set(email, verificationData);

    OTPService.cleanupExpiredEntries(global.preRegistrationCache);

    await EmailService.sendPreRegistrationOTP(email, otp);

    return res
        .status(200)
        .json(
            new ApiResponse(
                200,
                { email },
                "Verification OTP sent to your email. Please verify to continue registration."
            )
        );
});

// Verify Pre-registration Email OTP
const verifyPreRegistrationOTP = asyncHandler(async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        throw new ApiError(400, "Email and OTP are required");
    }

    if (!OTPService.validateOTPFormat(otp)) {
        throw new ApiError(400, "Invalid OTP format");
    }

    global.preRegistrationCache = global.preRegistrationCache || new Map();
    const verificationData = global.preRegistrationCache.get(email);

    if (!verificationData) {
        throw new ApiError(404, "No verification request found for this email");
    }

    if (OTPService.isOTPExpired(verificationData.otpExpiry)) {
        global.preRegistrationCache.delete(email);
        throw new ApiError(400, "OTP has expired. Please request a new one.");
    }

    if (verificationData.otp !== otp) {
        throw new ApiError(400, "Invalid OTP");
    }

    verificationData.isVerified = true;
    verificationData.verifiedAt = new Date();
    global.preRegistrationCache.set(email, verificationData);

    return res
        .status(200)
        .json(
            new ApiResponse(
                200,
                { email, verified: true },
                "Email verified successfully. You can now complete your registration."
            )
        );
});

// Check Pre-registration Email Verification Status
const checkPreRegistrationStatus = asyncHandler(async (req, res) => {
    const { email } = req.params;

    if (!email) {
        throw new ApiError(400, "Email is required");
    }

    global.preRegistrationCache = global.preRegistrationCache || new Map();
    const verificationData = global.preRegistrationCache.get(email);

    if (!verificationData) {
        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    { email, verified: false, exists: false },
                    "No verification found"
                )
            );
    }

    if (
        OTPService.isOTPExpired(verificationData.otpExpiry) &&
        !verificationData.isVerified
    ) {
        global.preRegistrationCache.delete(email);
        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    { email, verified: false, expired: true },
                    "Verification expired"
                )
            );
    }

    return res.status(200).json(
        new ApiResponse(
            200,
            {
                email,
                verified: verificationData.isVerified,
                exists: true,
                expiresAt: verificationData.otpExpiry,
            },
            verificationData.isVerified
                ? "Email verified"
                : "Email verification pending"
        )
    );
});

// Register User (You must need to verify email before register new user)
const registerUser = asyncHandler(async (req, res) => {
    const {
        mobile,
        firstName,
        lastName,
        email,
        gender,
        address,
        state,
        password,
    } = req.body;

    if (
        [
            mobile,
            firstName,
            lastName,
            email,
            gender,
            address,
            state,
            password,
        ].some((field) => field?.trim === "")
    ) {
        throw new ApiError(400, "All fields are required");
    }

    global.preRegistrationCache = global.preRegistrationCache || new Map();
    const verificationData = global.preRegistrationCache.get(email);

    if (!verificationData || !verificationData.isVerified) {
        throw new ApiError(
            400,
            "Email must be verified before registration. Please verify your email first."
        );
    }

    const existingUserEmail = await User.findOne({ email });
    if (existingUserEmail) {
        throw new ApiError(409, "User with this email already exists");
    }

    const existingUserPhone = await User.findOne({ mobile });
    if (existingUserPhone) {
        throw new ApiError(409, "User with this phone number already exists");
    }

    const user = await User.create({
        mobile,
        firstName,
        lastName,
        email,
        gender,
        address,
        state,
        password,
        playerId: generatePlayerId(),
        isActive: true,
        isEmailVerified: true,
    });

    global.preRegistrationCache.delete(email);

    // Send welcome email
    await EmailService.sendWelcomeEmail(email, firstName);

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );

    if (!createdUser) {
        throw new ApiError(
            500,
            "Something went wrong while registering the user"
        );
    }

    return res
        .status(201)
        .json(
            new ApiResponse(
                201,
                createdUser,
                "User registered successfully. Welcome!"
            )
        );
});

// Verify Email OTP 
const verifyEmailOTP = asyncHandler(async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        throw new ApiError(400, "Email and OTP are required");
    }

    if (!OTPService.validateOTPFormat(otp)) {
        throw new ApiError(400, "Invalid OTP format");
    }

    const user = await User.findOne({ email });

    if (!user) {
        throw new ApiError(404, "User not found");
    }

    if (user.isEmailVerified) {
        throw new ApiError(400, "Email already verified");
    }

    if (!user.otp || user.otp !== otp) {
        throw new ApiError(400, "Invalid OTP");
    }

    if (OTPService.isOTPExpired(user.otpExpiry)) {
        throw new ApiError(400, "OTP has expired");
    }

    user.isEmailVerified = true;
    user.isActive = true;
    user.otp = undefined;
    user.otpExpiry = undefined;
    await user.save({ validateBeforeSave: false });

    await EmailService.sendWelcomeEmail(user.email, user.firstName);

    return res
        .status(200)
        .json(
            new ApiResponse(
                200,
                {},
                "Email verified successfully. You can now login."
            )
        );
});

// Resend OTP (Need context Like: "register" or "login")
const resendOTP = asyncHandler(async (req, res) => {
    const { email, context } = req.body;

    if (!email || !context || !["register", "login"].includes(context)) {
        throw new ApiError(
            400,
            "Email and valid context ('register' or 'login') are required"
        );
    }

    const now = new Date();

    if (context === "register") {
        global.preRegistrationCache = global.preRegistrationCache || new Map();
        const data = global.preRegistrationCache.get(email);

        if (data && data.lastSent && now - data.lastSent < 60000) {
            throw new ApiError(
                429,
                "OTP already sent recently. Please wait a few seconds before retrying."
            );
        }

        // Re-generate OTP and expiry
        const otp = EmailService.generateOTP();
        const otpExpiry = OTPService.createOTPExpiry();

        const updatedData = {
            email,
            otp,
            otpExpiry,
            isVerified: false,
            createdAt: data?.createdAt || now,
            lastSent: now,
        };

        global.preRegistrationCache.set(email, updatedData);
        await EmailService.sendPreRegistrationOTP(email, otp);

        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    {},
                    "Registration OTP resent to your email."
                )
            );
    }

    const user = await User.findOne({ email });
    if (!user) {
        throw new ApiError(404, "User not found");
    }

    if (user.isEmailVerified !== true || user.isActive !== true) {
        throw new ApiError(403, "Account is not verified or active");
    }

    if (user.loginOtpSentAt && now - new Date(user.loginOtpSentAt) < 60000) {
        throw new ApiError(
            429,
            "OTP already sent recently. Please wait a few seconds before retrying."
        );
    }

    const otp = EmailService.generateOTP();
    const otpExpiry = OTPService.createOTPExpiry();

    user.loginOtp = otp;
    user.loginOtpExpiry = otpExpiry;
    user.loginOtpSentAt = now;
    await user.save({ validateBeforeSave: false });

    await EmailService.sendLoginOTP(user.email, otp, user.firstName);

    return res
        .status(200)
        .json(new ApiResponse(200, {}, "Login OTP resent to your email."));
});

// Login User
const loginUser = asyncHandler(async (req, res) => {
    const { mobile, email, password, otp, loginType } = req.body;

    if (!email && !mobile) {
        throw new ApiError(400, "Email or Phone is required");
    }

    if (!loginType || !["password", "otp"].includes(loginType)) {
        throw new ApiError(
            400,
            "Login type must be either 'password' or 'otp'"
        );
    }

    const user = await User.findOne({
        $or: [{ mobile }, { email }],
    });

    if (!user) {
        throw new ApiError(404, "User does not exist");
    }

    if (!user.isActive) {
        throw new ApiError(401, "Account is deactivated or not verified");
    }

    if (loginType === "password") {
        if (!password) {
            throw new ApiError(400, "Password is required for password login");
        }

        const isPasswordValid = await user.isPasswordCorrect(password);

        if (!isPasswordValid) {
            throw new ApiError(401, "Invalid user credentials");
        }
    } else if (loginType === "otp") {
        if (!otp) {
            throw new ApiError(400, "OTP is required for OTP login");
        }

        if (!OTPService.validateOTPFormat(otp)) {
            throw new ApiError(400, "Invalid OTP format");
        }

        if (email) {
            if (!user.loginOtp || user.loginOtp !== otp) {
                throw new ApiError(400, "Invalid OTP");
            }

            if (OTPService.isOTPExpired(user.loginOtpExpiry)) {
                throw new ApiError(400, "OTP has expired");
            }

            // Clear OTP after login
            user.loginOtp = undefined;
            user.loginOtpExpiry = undefined;
        } else if (mobile) {
            // Mobile OTP login (static OTP)
            const mobileOTP = OTPService.generateMobileOTP();
            if (otp !== mobileOTP) {
                throw new ApiError(400, "Invalid OTP");
            }
        }
    }

    user.lastActive = new Date();
    await user.save({
        validateBeforeSave: false,
    });

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
        user._id
    );

    const loggedInUser = await User.findById(user._id).select(
        "-password -refreshToken -otp -loginOtp"
    );

    const options = {
        httpOnly: true,
        secure: true,
    };

    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(
                200,
                {
                    loggedInUser,
                    accessToken,
                    refreshToken,
                },
                "User Logged In Successfully"
            )
        );
});

// Send Login OTP
const sendLoginOTP = asyncHandler(async (req, res) => {
    const { email, mobile } = req.body;

    if (!email && !mobile) {
        throw new ApiError(400, "Email or mobile is required");
    }

    const user = await User.findOne({
        $or: [{ mobile }, { email }],
    });

    if (!user) {
        throw new ApiError(404, "User does not exist");
    }

    if (!user.isActive) {
        throw new ApiError(401, "Account is deactivated or not verified");
    }

    if (email) {
        const otp = EmailService.generateOTP();
        const otpExpiry = OTPService.createOTPExpiry();

        user.loginOtp = otp;
        user.loginOtpExpiry = otpExpiry;
        await user.save({ validateBeforeSave: false });

        await EmailService.sendLoginOTP(email, otp, user.firstName);

        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    {},
                    "Login OTP sent successfully to your email"
                )
            );
    } else if (mobile) {
        // For mobile, return static OTP info
        const mobileOTP = OTPService.generateMobileOTP();

        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    { otp: mobileOTP },
                    "Use this OTP for mobile login"
                )
            );
    }
});

// Logout User
const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: {
                refreshToken: 1,
            },
        },
        {
            new: true,
        }
    );

    const options = {
        httpOnly: true,
        secure: true,
    };

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged out"));
});

// Refresh Access Token
const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken =
        req.cookies.refreshToken || req.body.refreshToken;

    if (!incomingRefreshToken) {
        throw new ApiError(401, "Unauthorized request");
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        );

        const user = await User.findById(decodedToken?._id);

        if (!user) {
            throw new ApiError(401, "Invalid refresh token");
        }

        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or used");
        }

        const options = {
            httpOnly: true,
            secure: true,
        };

        const { accessToken, refreshToken: newRefreshToken } =
            await generateAccessAndRefreshTokens(user._id);

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    { accessToken, refreshToken: newRefreshToken },
                    "Access token refreshed"
                )
            );
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token");
    }
});

// Change Current Password
const changeCurrentPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    const user = await User.findById(req.user._id);
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

    if (!isPasswordCorrect) {
        throw new ApiError(400, "Invalid old password");
    }

    user.password = newPassword;
    await user.save({ validateBeforeSave: false });

    return res
        .status(200)
        .json(new ApiResponse(200, {}, "Password changed successfully"));
});

module.exports = {
    sendPreRegistrationOTP,
    verifyPreRegistrationOTP,
    checkPreRegistrationStatus,
    registerUser,
    verifyEmailOTP,
    resendOTP,
    loginUser,
    sendLoginOTP,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
};
