const createError = require("http-errors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const userModel = require("./userModel");
const questionModel = require("../questions/questionModel");
const { generateAccessToken, generateRefreshToken } = require("../utils/auth");
const config = require("../config/config");

const passwordRegex =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

const usernameRegex = /^[a-zA-Z0-9._-]{3,20}$/;

const registerUser = async (req, res, next) => {
  const { fullname, username, email, password, country, role } = req.body;
  if (!fullname || !username || !email || !country || !password) {
    const error = createError(400, "All fields are required.");
    return next(error);
  }

  if (!usernameRegex.test(username)) {
    const error = createError(
      400,
      "Username must be alphanumeric and between 3 to 20 characters long."
    );
    return next(error);
  }

  if (!passwordRegex.test(password)) {
    const error = createError(400, "Password must be strong!");
    return next(error);
  }

  try {
    const existingUsername = await userModel.findOne({ username });
    if (existingUsername) {
      const error = createError(400, "Username is already taken.");
      return next(error);
    }

    const existingEmail = await userModel.findOne({ email });
    if (existingEmail) {
      const error = createError(400, "Email is already registered.");
      return next(error);
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await userModel.create({
      fullname,
      username,
      email,
      password: hashedPassword,
      country,
      role: role || "user",
    });

    res.status(200).json({
      StatusCode: 200,
      IsSuccess: true,
      ErrorMessage: [],
      Result: {
        message: "User registered successfully",
        user_data: newUser,
      },
    });
  } catch (error) {
    next(createError(500, "Server Error while creating new user."));
  }
};

const loginUser = async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return next(createError(400, "All feilds are required!"));
  }

  try {
    const user = await userModel.findOne({ email });
    if (!user) {
      return next(createError(404, "User not found!"));
    }
    const passMatch = await bcrypt.compare(password, user.password);
    if (!passMatch) {
      return next(createError(401, "Incorrect email and password !"));
    }

    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      maxAge: 30 * 60 * 1000,
    });
    user.refreshToken = refreshToken;
    try {
      await user.save();
    } catch (error) {
      console.log("Error saving user: ", error);
    }

    const userObj = user.toObject();
    delete userObj.password;
    delete userObj.refreshToken;

    res.status(200).json({
      StatusCode: 200,
      IsSuccess: true,
      ErrorMessage: [],
      Result: {
        message: "Login Sucessfully",
        accessToken: accessToken,
        refreshToken: refreshToken,
        user_data: userObj,
      },
    });
  } catch (error) {
    return next(createError(500, "Server error while login."));
  }
};

const refreshAccessToken = async (req, res, next) => {
  const incomingRefreshToken = req.body.refreshToken;
  const previousAccessToken = req.cookies.accessToken;
  if (!incomingRefreshToken) {
    return next(
      createError(401, "Unauthorized request: No refresh token provided")
    );
  }

  let decodedToken;
  try {
    decodedToken = jwt.verify(incomingRefreshToken, config.refreshTokenSecret);
  } catch (error) {
    return next(createError(401, "Invalid access token"));
  }

  const userId = decodedToken.sub;

  const newAccessToken = generateAccessToken(userId);

  res.cookie("accessToken", newAccessToken, {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    maxAge: 30 * 60 * 1000,
  });

  res.status(200).json({
    previousAccessToken: previousAccessToken,
    accessToken: newAccessToken,
  });
};

const getAllUsers = async (req, res, next) => {
  try {
    const user = await userModel.find({});
    res.json({
      StatusCode: 200,
      IsSuccess: true,
      ErrorMessage: [],
      Result: {
        message: "Successfully fetch all users",
        All_user: user,
      },
    });
  } catch (error) {
    return next(createError(500, "Server error while fetching users."));
  }
};

const options = {
  httpOnly: true,
  secure: true,
  sameSite: "Strict",
};

const handleLogout = async (req, res, next) => {
  try {
    res.clearCookie("refreshToken", options);
    res.clearCookie("accessToken", options);

    if (req.session) {
      req.session.destroy((err) => {
        if (err) {
          return next(err);
        }
        res.status(200).json({
          StatusCode: 200,
          IsSuccess: true,
          ErrorMessage: [],
          Result: {
            message: "Logout successful",
          },
        });
      });
    } else {
      res.status(200).json({
        StatusCode: 200,
        IsSuccess: true,
        ErrorMessage: [],
        Result: {
          message: "Logout successful",
        },
      });
    }
  } catch (error) {
    next(createError(500, "Server error while logging out."));
  }
};

const getUserById = async (req, res, next) => {
  const userId = req.params.id;
  try {
    const user = await userModel.findById(userId);
    if (!user) {
      return next(createError(404, "User not found."));
    }
    res.json(user);
  } catch (error) {
    return next(createError(500, "Server error while fetch user by ID."));
  }
};

const handleUserDelete = async (req, res, next) => {
  const userId = req.params.id;
  try {
    const user = await userModel.findByIdAndDelete(userId);
    if (!user) {
      return next(createError(404, "User not found."));
    }
    res.json({
      StatusCode: 200,
      IsSuccess: true,
      ErrorMessage: [],
      Result: {
        message: "User deleted successfully",
      },
    });
  } catch (error) {
    return next(createError(500, "Server error while deleting user."));
  }
};

const getUserSolvedQuizes = async (req, res, next) => {
  const userId = req.params.id;

  try {
    // Find the user by ID to get the solved quizzes IDs
    const user = await userModel.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Retrieve the IDs of solved quizzes from the User model
    const solvedQuizIds = user.solvedQuizzes;

    // Query the Question model to fetch details of solved quizzes
    const solvedQuizzes = await Promise.all(
      solvedQuizIds.map(async (quizId) => {
        try {
          // Find the question by its _id using findById
          const question = await questionModel.findOne({ "quiz._id": quizId });

          if (!question) {
            return null; // Handle case where question is not found
          }

          // Find the specific quiz object within the question's quiz array
          const quiz = question.quiz.find((q) => q._id.equals(quizId));

          if (!quiz) {
            return null; // Handle case where quiz is not found within the question
          }

          // Format the quiz data as needed
          return {
            questionId: question._id,
            title: question.title,
            quiz: {
              _id: quiz._id,
              question_text: quiz.question_text,
              answer: quiz.answer,
              hint: quiz.hint,
            },
          };
        } catch (error) {
          console.error("Error fetching quiz:", error.message);
          return null; // Handle error fetching quiz
        }
      })
    );

    // Filter out any null values (if quiz not found)
    const filteredQuizzes = solvedQuizzes.filter((quiz) => quiz !== null);

    res.status(200).json({
      message: "Solved quizzes fetched successfully",
      solved_quizzes: filteredQuizzes,
    });
  } catch (error) {
    console.error("Error fetching solved quizzes:", error.message);
    res.status(500).json({ message: `Server error: ${error.message}` });
  }
};

module.exports = {
  registerUser,
  loginUser,
  handleLogout,
  getAllUsers,
  getUserById,
  handleUserDelete,
  refreshAccessToken,
  getUserSolvedQuizes,
};
