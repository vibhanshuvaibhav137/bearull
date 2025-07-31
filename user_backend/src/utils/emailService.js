const { SESClient, SendEmailCommand } = require("@aws-sdk/client-ses");
const { ApiError } = require("./ApiError");

const sesClient = new SESClient({
    region: process.env.AWS_SES_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
});

class EmailService {
    static generateOTP() {
        return Math.floor(100000 + Math.random() * 900000).toString();
    }

    static async sendEmail(to, subject, htmlContent) {
        const params = {
            Destination: {
                ToAddresses: [to],
            },
            Message: {
                Body: {
                    Html: {
                        Charset: "UTF-8",
                        Data: htmlContent,
                    },
                },
                Subject: {
                    Charset: "UTF-8",
                    Data: subject,
                },
            },
            Source: process.env.AWS_SES_FROM_EMAIL,
        };

        try {
            const command = new SendEmailCommand(params);
            const response = await sesClient.send(command);
            console.log("Email sent:", response.MessageId);
            return response;
        } catch (error) {
            console.error("Error sending email:", error);
            throw new ApiError(500, "Failed to send email");
        }
    }

    static async sendPreRegistrationOTP(email, otp) {
        const htmlContent = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333;">Email Verification Required</h2>
                <p>Thank you for starting your registration process!</p>
                <p>Your verification OTP is: <strong style="font-size: 24px; color: #007bff;">${otp}</strong></p>
                <p>This OTP is valid for 10 minutes.</p>
                <p>Please enter this OTP to verify your email address and complete your registration.</p>
                <hr>
                <p style="color: #666; font-size: 12px;">If you didn't request this verification, please ignore this email.</p>
            </div>
        `;

        return await this.sendEmail(
            email,
            "Verify Your Email - Registration",
            htmlContent
        );
    }

    static async sendLoginOTP(email, otp, firstName) {
        const htmlContent = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333;">Login OTP</h2>
                <p>Hello ${firstName},</p>
                <p>You requested to login using OTP. Your login OTP is:</p>
                <p style="text-align: center; background: #f8f9fa; padding: 20px; border-radius: 5px;">
                    <strong style="font-size: 32px; color: #007bff; letter-spacing: 3px;">${otp}</strong>
                </p>
                <p>This OTP is valid for 10 minutes.</p>
                <p>If you didn't request this login, please secure your account immediately.</p>
                <hr>
                <p style="color: #666; font-size: 12px;">This is an automated message, please do not reply.</p>
            </div>
        `;

        return await this.sendEmail(email, "Your Login OTP", htmlContent);
    }

    static async sendOTP(email, otp, firstName) {
        const htmlContent = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333;">Email Verification</h2>
                <p>Hello ${firstName},</p>
                <p>Your OTP for email verification is: <strong style="font-size: 24px; color: #007bff;">${otp}</strong></p>
                <p>This OTP is valid for 10 minutes.</p>
                <hr>
                <p style="color: #666; font-size: 12px;">If you didn't request this, please ignore this email.</p>
            </div>
        `;

        return await this.sendEmail(
            email,
            "Your OTP for Verification",
            htmlContent
        );
    }

    static async sendWelcomeEmail(email, firstName) {
        const htmlContent = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #28a745;">Welcome to Bearull!</h2>
                <p>Hello ${firstName},</p>
                <p>Welcome to Bearull! Your account has been successfully created and verified.</p>
                <p>You can now access all the features available to you.</p>
                <p>If you have any questions, feel free to contact our support team.</p>
                <hr>
                <p style="color: #666; font-size: 12px;">Thank you for joining us!</p>
            </div>
        `;

        return await this.sendEmail(
            email,
            "Welcome to Bearull!",
            htmlContent
        );
    }
}

module.exports = { EmailService };
