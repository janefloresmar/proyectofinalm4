const catchAsync = require("../utils/catchAsync");
const Cart = require('../models/Cart');
const Product = require('../models/Product');
const User = require('../models/User');
const { default: mongoose } = require("mongoose");
const { find, deleteOne, findOne } = require("../models/Cart");

exports.getAllCart = catchAsync(async (req, res) => {
  const products = await Cart.find();

  res.status(200).json({
    status: "success",
    timeOfRequest: req.requestTime,
    results: products.length,
    data: {
      products,
    },
  });
});


const addProductToShoppingCart = async (product) => {
  const newProductOnCart = await Cart.updateOne({$push:{products:product}})
  return newProductOnCart
}

const checkProducts = async (product)=>{
    const thereIsProductDB = await Product.findOne(product)
    if(thereIsProductDB){
      const addProductOnCart = addProductToShoppingCart(thereIsProductDB)
      return addProductOnCart
    }

    const message = "No product in our database to select, add one in get products" 
    return message
}

const checkProductsOnCart = async (product, user) =>{
  const userAunthenticated = await User.find(user)
  if(userAunthenticated){
    const checkingCar = await Cart.findOne(product)
    return checkingCar.products.find(prod => prod.productName == product.productName)
  }

}

const createShoppingCart = async (user, product) => {
  const createCart = await Cart.create({user:user.userName, status:"pending", products:product})
  return createCart
}

const existShoppingCart = async (user, product)=>{
  const foundShoppingCart = await Cart.find({a:1})
  if(foundShoppingCart == ''){
    return createShoppingCart(user, product)
  }else{
    return checkProductsOnCart(product, user)
  }
}

exports.addProductToShoppingCart = catchAsync(async (req, res) => {

    const userProduct = req.body;
    const user = req.user;
    let message = "";
    await existShoppingCart(user, userProduct);
    const product = await checkProductsOnCart(userProduct, user);
    if(product){
      message = "Ya existe ese producto en tu carrito de compras"
      res.status(200).json({
        message: message,
        status: "succes",
        user: user.userName,
        data: {
          product
        },
      });

    }else{
      message = "No tienes ese producto en tu carrito. Agregaremos el producto si se encuentra en la base de datos"
      
      const getCheckProducts = await checkProducts(userProduct)
      const modifyingData = getCheckProducts.modifiedCount    
      if(typeof(getCheckProducts) == String){
        message = addedProduct
        res.status(400).json({
          message: message,
          status: "fail"
        })
      }else{
        res.status(200).json({
          message: message,
          status: "succes",
          user: user.userName,
          documentModified: modifyingData,
          statusCart:"pending",
        });    
      } 
    }
});

const changeCartStatus = async (user, cartStatus, statusByUser) => {
  const searchingUser = await Cart.findOne({user})
  const getUserStatus = statusByUser.status
  if(searchingUser.user == user && cartStatus == "pending"){
    const changingStatus = await Cart.updateOne({status: getUserStatus})
    return changingStatus
  }
}

exports.payShoppingCart = catchAsync(async(req, res) => {
    const {userName} = req.user
    const statusModifiedByUser = req.body

    const checkingCar = await Cart.find({a:1})
    
    if(checkingCar != null){
      const userCart = checkingCar.find(userCart => userCart.user == userName)
      await changeCartStatus(userName,userCart.status, statusModifiedByUser);
      const productPrice = await Cart.findOne().select('products');
      const totalPrice = await productPrice.products.reduce((prevPrice, nextPrice) => parseFloat(prevPrice.price + nextPrice.price));
      
      res.status(200).json({
        message:"if your status is pending you must change it to pay",
        user: userName,
        status: userCart.status,
        products: productPrice,
        totalPrice: totalPrice,
      });  
    }else{
      res.status(200).json({
        message:"the status is pending, if you want to continue must change the status to pay",
        status: "fail",
      });  
    }
});


async function searchProduct(productId){
    const findCart = await Cart.find().select('products')
    const productFound = findCart[0].products.find(prod => prod._id == productId)
    if(productFound){
      return productFound
    }else{
      let message = "Error"
      return message
    }
}

exports.deleteShoppingCart = catchAsync(async (req, res) => {
  const id = req.params.id
  const {userName} = req.user
  const product = await searchProduct(id)

  if(typeof(product) == String){
    res.status(200).json({
      message: product,
      status: "succes",
      user: userName,
    });  
  }else{
    const statusCart = await Cart.find().select('status')
    const eraseFile = await Cart.updateOne({$pull: {products: product}})
    const {acknowledged, modifiedCount} = eraseFile
    res.status(200).json({
      status: "succes",
      user: userName,
      statusCart:statusCart[0].status,
      data: {
        acknowledged,
        modifiedCount
      },
    });    
  }
});