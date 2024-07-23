const express = require("express");
const { isAdmin, authenticateToken, isUser } = require("../middlewares/authHandle");

const {
  createQuestionSet,
  getAllQuestion,
  getSingleQuestion,
  updateQuestionSet,
  deleteSubQuestion,
  deleteQuestionSet,
  getQuestionByTopic,
} = require("./questionController");

const questionRouter = express.Router();

questionRouter.post("/create", authenticateToken, isAdmin, createQuestionSet);
questionRouter.get(
  "/getAllQuestion",
  authenticateToken,
  isUser,
  getAllQuestion
);

questionRouter.post(
  "/update/:id",
  authenticateToken,
  isAdmin,
  updateQuestionSet
);
questionRouter.delete(
  "/delete/:id",
  authenticateToken,
  isAdmin,
  deleteQuestionSet
);
questionRouter.delete(
  "/delete/questions/:questionId/subQuestions/:subQuestionId",
  authenticateToken,
  isAdmin,
  deleteSubQuestion
);
questionRouter.get(
  "/getQuestion/:id",
  authenticateToken,
  isUser,
  getSingleQuestion
);

questionRouter.get(
  "/getQuestionByTopic/:topicId",
  authenticateToken,
  isAdmin,
  getQuestionByTopic
);

module.exports = questionRouter;
