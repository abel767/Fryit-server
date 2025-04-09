const express = require('express');
const router = express.Router();
const {
   register,
   verifyEmail,
   login,
   refreshToken, // Added missing import
   googleAuth,
   googleCallback,
   logout // Added missing import
} = require('../controllers/authController');

const upload = require('../utils/upload'); // Fixed: Import should be direct, not destructured
const { protect } = require('../middlewares/authMiddleware');

// Public routes 
router.post('/register', upload.single('avatar'), register);
router.post('/verify-email', verifyEmail);
router.post('/login', login);
router.post('/refresh-token', refreshToken);
router.get('/google', googleAuth);
router.get('/google/callback', googleCallback);

// Protected routes (requires valid JWT)
router.get('/logout', protect, logout);

module.exports = router;