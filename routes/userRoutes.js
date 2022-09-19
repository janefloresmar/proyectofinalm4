const express = require("express");
const userController = require("./../controllers/userController");
const userRouter = express.Router();
const authController = require('../controllers/authController')




userRouter
  .route("/")
  .all(authController.protect)
  .get(userController.getAllusers)
  .post(userController.addUser);
userRouter.route("/:id")
.all(authController.protect)
.get(userController.getUserById)
.put(userController.updateUser)
.delete(userController.deleteUser);

module.exports = userRouter;
