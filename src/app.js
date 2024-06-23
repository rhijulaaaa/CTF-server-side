require("dotenv").config();
const express = require("express");
const { createHttpError } = require("http-errors");
const globalErrorHandler = require("./middlewares/globalErrorHandler");
const userRouter = require("./users/userRouter");

const app = express();
app.use(express.json());

// Routes
app.get("/", (req, res, next) => {
  const error = createHttpError(400, "Somthing went wrong !");
  throw error;
  res.json({ message: "Welcome to CTN.." });
});

app.use("/api/users", userRouter);
app.use(globalErrorHandler);

module.exports = app;
