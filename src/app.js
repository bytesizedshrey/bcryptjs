const express = require('express')
const authRouter = require("./routes/auth.routes") //Plugging in Auth Routes
const cookieParser = require("cookie-parser")

const app = express()

app.use(express.json()) //Middleware Activated
app.use(cookieParser()) //Middleware Activated
app.use("/api/auth",authRouter) //Plugging in Auth Routes

module.exports = app