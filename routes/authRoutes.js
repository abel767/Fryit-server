const express = require('express')
const router = express.Router()
const {
   register,
   verifyEmail,
   login,
   googleAuth,
   googleCallback
} = require('../controllers/authController')
