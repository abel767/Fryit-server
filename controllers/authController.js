const User = require('../models/User')
const jwt = require('jsonwebtoken')
const otpGenerator = require('otp-generator')
const sendEmail = require('../utils/sendEmail')
const {upload} = require('../utils/upload')
const passport = require('passport')


const generateTokens = async(user, req) =>{
    const accessToken = jwt.sign(
        {id: user._id},
        process.env.JWT_SECRET,
        {expiresIn: process.env.ACCESS_TOKEN_EXPIRE}
    )
    const refreshToken = jwt.sign(
        {id: user._id},
        process.env.JWT_SECRET,
        {expiresIn: process.env.ACCESS_TOKEN_EXPIRE}
    )

    user.refreshToken = refreshToken
    user.refreshTokenExpires = new Date(
        Date.now() + process.env.REFRESH_TOKEN_COOKIE_EXPIRE * 24  * 60 * 60 * 1000
    )
    await user.save({validateBeforeSave: false})

    res.cookie('accessToken', accessToken, {
        expires: new Date(Date.now() + process.env.ACCESS_TOKEN_COOKIE_EXPIRE * 60 * 1000),
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    })

    res.cookie('refreshToken', refreshToken, {
        expires: new Date(Date.now() + process.env.REFRESH_TOKEN_COOKIE_EXPIRE * 24 * 60 * 60 * 1000),
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    })

    //removing sensitive fields before sending user data
    user.password = undefined
    user.refreshToken = undefined
    user.verificationCode = undefined

    return {accessToken, refreshToken, user}
}

exports.register = async(req,res,next)=>{

    try{
        const {username, email, password, role} = req.body

        //check if user exists
        const existingUser = await User.findOne({email})
        if(existingUser){
            return res.status(400).json({
                success: false,
                message: 'User already exists'
            })
        }
        //create user
        const user = new User({
            username,
            email,
            password,
            role: role || 'user'
        })

        if(req.file) {
            const result = await uploadToCloudinary(req.file)
            user.avatar = result.secure_url
        }

        // otp generation

        const otp = otpGenerator.generate(4,{
            uppercase: false,
            specialChars: false,
            alphabets: false
        })

        user.verificationCode = otp;
        user.verificationCodeExpires = Date.now() + 10 * 60 * 1000

        await user.save()

        const message= `
        <h1>Welcome to IndieVerse!</h1>
      <p>Your verification code is: <strong>${otp}</strong></p>
      <p>This code expires in 10 minutes.</p>
       `;

       await sendEmail({
        email: user.email,
        subject: 'Email Verification',
        html: message
       })

       res.status(201).json({
        success: true,
        message: 'Verification code sent to email'
       })
    }catch(err){
        next(err)
    }
}


// verifying email

exports.verifyEmail = async(req,res,next)=>{
    try{
        const {code, email} = req.body

        const user = await User.findOne({
            email,
            verificationCode: code,
            verificationCodeExpires: {$gt: Date.now()}
        })

        if(!user){
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired verification code'
            })
        }

        user.isVerified = true;
        user.verificationCode = undefined;
        user.verificationCodeExpires = undefined

        await user.save()

        // generate tokens and send response
        const {accessToken, refreshToken, user: userData} = await generateTokens(user, res)

        res.status(200).json({
            success: true,
            accessToken,
            refreshToken,
            user: userData
        })
    }catch(err){
        next(err)
    }
}

exports.login = async(req,res,next)=>{
    try{
        const {email , password} = req.body

        if(!email || !password){
            return res.status(400).json({
                success: false,
                message: `Please provide email and password`
            })
        }

        // check for user 
        const user = await User.findOne({email}).select('+password')

        if(!user || !(await user.comparePassword(password))){
            return res.status(400).json({
                success: false,
                message: 'Invalid credentials'
            })
        }

        if(!user.isVerified){
            return res.status(401).json({
                success: false,
                message: 'Please verify your email first'
            })
        }

        const {accessToken, refreshToken, user: userData} = await generateTokens(user, res)

        res.status(200).json({
            success: true,
            accessToken,
            refreshToken,
            user: userData
        })
    }catch(err){
        next(err)
    }
}


exports.refreshToken = async(req,res,next) =>{
    try{
        const {refreshToken} = req.cookies

        if(!refreshToken){
            return res.status(401).json({
                success: false,
                message: `No refresh token provided`
            })
        }

        // verify refreshToken
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET)

        // check if user exists with this refresh token

        const user = await User.findOne({
            _id: decoded.id,
            refreshToken,
            refreshTokenExpires: {$gt: Date.now()}
        })

        if(!user){
            return res.status(401).josn({
                success: false,
                message: 'Invalid refresh token'
            })
        }

        // Generate new access token
        const newAccessToken = jwt.sign(
            {id: user._id},
            process.env.JWT_SECRET,
            {expiresIn: process.env.ACCESS_TOKEN_EXPIRE}
        )

        // set new access token cookeie 
        res.cookie('accessToken', newAccessToken, {
            expires: new Date(Date.now() + process.env.ACCESS_TOKEN_COOKIE_EXPIRE * 60 * 1000),
            httpOnly: true,
            secure: process.env.NODE_ENV = 'production',
            sameSite: 'strict'
        })

        res.status(200).json({
            succes: true,
            accessToken: newAccessToken
        })

    }catch(err){
        next(err)
    }
}


// Google Auth

exports.googleAuth = passport.authenticate('google', {
    scope: ['profile', 
        'email'
    ],
    prompt: 'select_account'
})


// google auth callback
exports.googleCallback = async (req, res, next)=>{
    passport.authenticate('google', async(err, user, info)=>{
        try{
            if(err || !user){
                return res.redirect(
                  `${process.env.FRONTEND_URL}/login?error=google-auth-failed`
                )
            }

            const {accessToken, refreshToken, user: userData} = await generateTokens(user, res)
            // redirect to frontedn with tokens in url (or use session)

            res.redirect(
                `${process.env.FRONTEND_URL}/auth/success?` + 
                `accessToken=${accessToken}&`+
                `refreshToken=${refreshToken}&` +
                `user=${encodeURIComponent(JSON.stringify(userData))}`
            )
        }catch(err){
            next(err)
        }
    })(req,res,next)
}


// logout user

exports.logout = async(req,res,next) => {
    try{
        res.clearCookie('accessToken')
        res.clearCookie('refreshToken')
      
        // remove refresh from db
        await User.findByIdAndUpdate(
            req.user.id,
            {
                refreshToken: undefined,
                refreshTokenExpires: undefined
            }
        )

        res.status(200).json({
            succes: true,
            message: 'Logged out successfully'
        })
    }catch(error){
        next(error)
    }
}