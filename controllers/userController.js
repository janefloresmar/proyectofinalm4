const crypto = require("crypto");
const User = require("../models/User");
const catchAsync = require("../utils/catchAsync");

exports.getAllusers = catchAsync(async (req, res) => {
  const users = await User.find();

  res.status(200).json({
    status: "success",
    timeOfRequest: req.requestTime,
    results: users.length,
    data: {
      users,
    },
  });
});

exports.addUser = catchAsync(async (req, res) => {
  req.body.password = crypto
    .createHash("sha256")
    .update(req.body.password)
    .digest("hex");

  let newUser = await User.create(req.body);
  newUser = newUser.toObject();
  delete newUser.password;

  res.status(200).json({
    status: "success",
    data: {
      user: newUser,
    },
  });
});

exports.getUserById = catchAsync(async (req, res) => {
  const foundUser = await User.findById(req.params.id);
  if (foundUser) {
    res.status(200).json({
      status: "success",
      data: {
        foundUser,
      },
    });
  } else {
    res.status(404).json({
      status: "not found",
    });
  }
});

exports.updateUser = catchAsync(async (req, res) => {
  const id = req.params.id
  const body = req.body
  const editUser = await User.findOneAndUpdate(id, body)
  
  res.status(200).json({
    status: "Modified File",
    data: {
      editUser
    },
  });
});

exports.deleteUser = catchAsync(async (req, res) => {
  
  const id = req.params.id
  const user = await User.findOneAndDelete(id)
  
  res.status(200).json({
    status: "deleted File",
    data: {
      user,
    },
  });
});
