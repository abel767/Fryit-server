require(dotenv).config()

const express = require('express')
const mongoose = require('mongoose')
const passport = require('passort')
const cors = require('cors')
const path = require('path')

// import routes 
const authRoutes = require('./routes/authRoutes')

// initializing app
const app = express()

// middlewares
app.use(express.json())
app.use(cors())
app.use(passport.initialize())
require('./config/passport')(passport)

// database connection
require('./config/db')

//routes 
app.use('/api/auth', authRoutes)

//Error handling middleware
app.use((err, req, res, next) =>{
    console.error(err.stack)
    res.status(500).json({success: false, message: 'Server Error'})
})

const PORT = process.env.PORT || 5000
app.listen(PORT, ()=> console.log(`Server is running on port ${PORT}`))

