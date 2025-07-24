const { asyncHandler } = require("../utils/asyncHandler");
const { ApiError } = require("../utils/ApiError");
const { User } = require("../models/user.model");
const { ApiResponse } = require("../utils/ApiResponse");
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
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const id = Array.from({ length: 8 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
    return `${id}-BEARULL`;
};

// Register User
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

    const existingUserEmail = await User.findOne({ email });

    if (existingUserEmail) {
        throw new ApiError(401, "User with this email already exist");
    }

    const existingUserPhone = await User.findOne({ mobile });

    if (existingUserPhone) {
        throw new ApiError(401, "User with this Phone already exist");
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
    });

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );

    if (!createdUser) {
        throw new ApiError(
            401,
            "Something went wrong while registering the user"
        );
    }

    return res
        .status(201)
        .json(
            new ApiResponse(200, createdUser, "User registered successfully")
        );
});

// Login User
const loginUser = asyncHandler(async (req, res) => {
    const { mobile, email, password } = req.body;

    if (!email && !mobile) {
        throw new ApiError(401, "Email or Phone is required");
    }

    const user = await User.findOne({
        $or: [{ mobile }, { email }],
    });

    if (!user) {
        throw new ApiError(404, "User dose not exist");
    }

    if (!user.isActive) {
        throw new ApiError(401, "Account is deactivated");
    }

    const isPasswrodVaild = await user.isPasswordCorrect(password);

    if (!isPasswrodVaild) {
        throw new ApiError(401, "Invalid user credentials");
    }

    user.lastActive = new Date();
    await user.save({
        validateBeforeSave: false,
    });

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
        user._id
    );

    const loggedInUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );

    const options = {
        httpOnly: true,
        secure: true,
    };

    return res
        .status(201)
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
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
};
