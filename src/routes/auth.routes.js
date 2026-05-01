const express = require('express')
const userModel = require("../models/user.model")
const jwt = require("jsonwebtoken");

const authRouter = express.Router() //defined a router

//Store in Database
authRouter.post("/register",async(req,res)=>{
    const {email,name,password} = req.body //Extract the Data

    const isUserAlreadyExists = await userModel.findOne({email})

    if(isUserAlreadyExists){
        return res.status(400).json({
            message : "User already exist with this email address."
        })
    }

    const user = await userModel.create({
        email,password,name
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

module.exports = authRouter //Export Router