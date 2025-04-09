const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Protect routes with JWT
exports.protect = async(req, res, next) => {
    let token;
    if(req.cookies.accessToken) {
        token = req.cookies.accessToken;
    } else if(req.headers.authorization?.startsWith('Bearer')) { // Fixed: startWith -> startsWith
        token = req.headers.authorization.split(' ')[1];
    }

    if(!token) {
        return res.status(401).json({
            success: false,
            message: 'Not authorized to access this route'
        });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Fixed: JWT_SCERET -> JWT_SECRET

        // Check if user still exists
        req.user = await User.findById(decoded.id);

        if(!req.user) {
            return res.status(401).json({
                success: false,
                message: 'User no longer exists'
            });
        }

        next();
    } catch(error) {
        return res.status(401).json({
            success: false,
            message: 'Not Authorized or token expired'
        });
    }
};

// Role based authorization
exports.authorize = (...roles) => {
    return (req, res, next) => {
        if(!roles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                message: `User role ${req.user.role} is unauthorized`
            });
        }
        next();
    };
};