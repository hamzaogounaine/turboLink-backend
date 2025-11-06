const express = require("express");
const cors = require("cors");
require("dotenv").config();
const authRoutes = require("./Routes/authRoutes");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.json());
app.use(cors({
    origin: process.env.FRONTEND_URL, // Allow only your frontend URL
    credentials: true,               // Essential for sending/receiving cookies
}));
app.use(cookieParser())
const PORT = process.env.PORT || 4000;
//auth routes
app.use(authRoutes);

//mongodb connect
const mongodb_uri = process.env.MONGODB_URI;
mongoose
  .connect(mongodb_uri)
  .then(() => {
    console.log("Connected to mongodb");
    app.listen(PORT, () => {
      console.log("Server is running");
    });
  })
  .catch((err) => {
    console.log(err);
    process.exit(1);
  });
  
