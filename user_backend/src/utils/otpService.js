const { ApiError } = require("./ApiError");

class OTPService {
    static generateMobileOTP() {
        // Static OTP for mobile as requested
        return "123456";
    }

    static generateEmailOTP() {
        return Math.floor(100000 + Math.random() * 900000).toString();
    }

    static createOTPExpiry() {
        // OTP expires in 10 minutes
        return new Date(Date.now() + 10 * 60 * 1000);
    }

    static isOTPExpired(otpExpiry) {
        return new Date() > otpExpiry;
    }

    static validateOTPFormat(otp) {
        return /^\d{6}$/.test(otp);
    }

    static cleanupExpiredEntries(cache) {
        if (!cache || typeof cache.forEach !== "function") return;

        const now = new Date();
        cache.forEach((value, key) => {
            if (value.otpExpiry && now > value.otpExpiry && !value.isVerified) {
                cache.delete(key);
            }
        });
    }
}

module.exports = { OTPService };
