const jwt = require('jsonwebtoken')
const User = require('../models/User')

// protect routes with jwt 

exports.protect = async(req,res,next)=>{
    let token;
    if(req.cookies.accessToken){
        token = req.cookies.accessToken
    }else if(req.headers.authorization?.startWith('Bearer')){
        token = req.headers.authorization.split(' ')[1]
    }

    if(!token){
        return res.status(401).json({
            success: false,
            message: 'Not authorized to access this route'
        })
    }

    try{
        const decoded = jwt.verify(token, process.env.JWT_SCERET)

        // check if user still exists

        req.user = await User.findById(decoded.id)

        if(!req.user){
            return res.status(401).json({
                success: false,
                message: 'User no longer exists'
            })
        }

        next()
    }catch(error){
        return res.status(401).json({
            success: false,
            message: 'Not Authorized or token expired'
        })
    }
}

// role based authorization
exports.authorize = (...roles) =>{
    return (req,res,next) =>{
        if(!roles.includes(req.user.role)){
            return res.status(403).json({
                success: false,
                message: `User role ${req.user.role} is unauthorized`
            })
        }
        next()
    }
}