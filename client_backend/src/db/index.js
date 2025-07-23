const mongoose = require("mongoose");
const { DB_NAME, CLIENT_NAME } = require("../constants");

const connectDB = async () => {
    try {
        const connectionInstance = await mongoose.connect(
            `${process.env.MONGODB_URL}/${DB_NAME}/${CLIENT_NAME}`,
            {
                useNewUrlParser: true,
                useUnifiedTopology: true,
            }
        );
        console.log(`\nMongoDB connected !! DB HOST : ${connectionInstance.connection.host}`);
    } catch (error) {
        console.log("MongoDB connection error", error);
        process.exit(1);
    }
};

module.exports = connectDB;
