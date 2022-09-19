const express = require("express");
const shoppingCartController = require("./../controllers/shoppingCartController.js");
const authController = require("./../controllers/authController");
const shoppingCartRouter = express.Router();



shoppingCartRouter.all('/', authController.protect)
shoppingCartRouter.get('/', shoppingCartController.getAllCart)
shoppingCartRouter.post('/product', authController.protect, shoppingCartController.addProductToShoppingCart)
shoppingCartRouter.post('/pay', authController.protect, shoppingCartController.payShoppingCart)
shoppingCartRouter.delete('/product/:id', authController.protect, shoppingCartController.deleteShoppingCart)

module.exports = shoppingCartRouter;