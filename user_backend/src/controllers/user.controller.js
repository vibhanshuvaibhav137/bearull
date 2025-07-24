const { asyncHandler } = require("../utils/asyncHandler");
const { ApiError } = require("../utils/ApiError");
const { ApiResponse } = require("../utils/ApiResponse");
const { User } = require("../models/user.model");

// Get User Profile
const getProfile = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id).select(
        "-password -refreshToken"
    );

    if (!user) {
        throw new ApiError(404, "User not found");
    }

    return res
        .status(200)
        .json(new ApiResponse(200, user, "Profile fetched successfully"));
});

// Update User Profile
const updateProfile = asyncHandler(async (req, res) => {
    const { mobile, firstName, lastName, email, gender, state, address } =
        req.body;
    const userId = req.user._id;

    const existingUserEmail = await User.findOne({ email });

    if (existingUserEmail) {
        throw new ApiError(401, "User with this email already exist");
    }

    const existingUserPhone = await User.findOne({ mobile });

    if (existingUserPhone) {
        throw new ApiError(401, "User with this Phone already exist");
    }

    const updateData = {};
    if (mobile) updateData.mobile = mobile;
    if (firstName) updateData.firstName = firstName;
    if (lastName) updateData.lastName = lastName;
    if (email) updateData.email = email;
    if (gender) updateData.gender = gender;
    if (address) updateData.address = address;
    if (state) updateData.state = state;

    const user = await User.findByIdAndUpdate(userId, updateData, {
        new: true,
        runValidators: true,
    }).select("-password -refreshToken");

    if (!user) {
        throw new ApiError(404, "User not found");
    }

    return res
        .status(200)
        .json(new ApiResponse(200, user, "Profile updated successfully"));
});

module.exports = {
    getProfile,
    updateProfile,
};
