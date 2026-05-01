const express = require('express')
const userModel = require("../models/user.model")
const jwt = require("jsonwebtoken");
const crypto = require("crypto")//for hashing the password

const authRouter = express.Router() //defined a router

//Store in Database
// controller
authRouter.post("/register",async(req,res)=>{
    const {email,name,password} = req.body //Extract the Data

    const isUserAlreadyExists = await userModel.findOne({email})

    if(isUserAlreadyExists){
        return res.status(409).json({
            message : "User already exist with this email address."
        })
    }

    //hash the password
    const hash = crypto.createHash("md5").update(password).digest("hex")

    const user = await userModel.create({
        email,password:hash,name
    })

    //server with signature(digital signature)
    const token = jwt.sign(
        {
            id: user._id,
            email: user.email
        },
        process.env.JWT_SECRET
    )

    res.cookie("jwt_token", token)//server will set token on the cookie

    //Send Response
    res.status(201).json({
        message : "user registered",
        user,
        token
    })
})

//Protected Route
// Check if cookie exists (e.g., token)
// Verify it (JWT / session)
// Allow or reject
authRouter.post("/protected",async(req,res)=>{
    console.log(req.cookies)

    res.status(200).json({
        message : "this is a protected route"
    })
})

//login route -> if right then generate a new token and give it to the user as a cookie
authRouter.post("/login", async (req,res)=>{
    const{email,password} = req.body

    //check if the user even exists or not
    const user = await userModel.findOne({email})

    if(!user){
        return res.status(404).json({
            message : "User not found with this email address."
        })
    }
    //if the email exists then check if the password is correct or not by hashing the password
    const isPasswordMatched = user.password === crypto.createHash("md5").update(password).digest("hex")//user.password is the hashed password in the Database

    if(!isPasswordMatched){
        return res.status(401).json({
            message : "Invalid Password. Please try again."
        })
    }
    //if password is correct then generate a new token and give it to the user as a cookie
     const token = jwt.sign({
        id: user._id,
     }, process.env.JWT_SECRET)

     res.cookie("jwt_token", token)

     res.status(200).json({
        message : "Login Successful",
        user,
     })

})

module.exports = authRouter //Export Router