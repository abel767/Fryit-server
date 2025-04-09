require('dotenv').config(); //

const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport'); // 
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');

// Import routes 
const authRoutes = require('./routes/authRoutes');

// Import database connection
const connectDB = require('./config/db');

// Initialize app
const app = express();

// Middlewares
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: process.env.FRONTEND_URL,
    credentials: true
}));
app.use(passport.initialize());
require('./config/passport')(passport);

// Connect to database
connectDB(); // Actually call the connectDB function

// Routes 
app.use('/api/auth', authRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ success: false, message: 'Server Error' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));