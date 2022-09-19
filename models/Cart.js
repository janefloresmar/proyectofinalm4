const mongoose = require("mongoose");
const shoppingCartSchema = new mongoose.Schema({
  user: {
    type: String,
    required: true,
    unique: true,
  },
  status: {
    type: String,
  },
  products: {
    type: [],
    required: true
  },
});






const shoppingCart = mongoose.model("shoppingCart", shoppingCartSchema);
module.exports = shoppingCart;
