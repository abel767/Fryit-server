const express = require('express')
const {protect, adminOnly} = require('../middlewares/authMiddleware')
const {getDashboardStats, getAllUsers, updateUserRole} = require('../controllers/adminController')

const router = express.Router()

router.use(protect, adminOnly)

router.get('/dashboard', getDashboardStats);

router.get('/users', getAllUsers)

router.patch('/user/:id/role', updateUserRole)

module.exports = router
