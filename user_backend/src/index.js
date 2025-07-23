const dotenv = require("dotenv");
const connectDB = require("./db/index");
const { app } = require("./app");

dotenv.config({
    path: './env'
});

connectDB()
    .then(() => {
        app.listen(process.env.PORT || 8000, () => {
            console.log(`Server is running at PORT : ${process.env.PORT}`);
        });
    })
    .catch((err) => {
        console.log("MONGO DB connection error !!!", err);
    });
