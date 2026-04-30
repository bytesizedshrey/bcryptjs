const mongoose = require("mongoose")
//for format
const userSchema = new mongoose.Schema({
    name : String,
    email : String,
    password : String,
})
//for operation 
const userModel = mongoose.model("user",userSchema)

module.exports = userModel