const User = require('../models/User');

// Get dashboard stats
const getDashboardStats = async (req, res) => {
  try {
    const stats = {
      totalUsers: await User.countDocuments(),
      totalAdmins: await User.countDocuments({ role: 'admin' }),
      totalDevelopers: await User.countDocuments({ role: 'developer' }),
    };
    res.json({ success: true, data: stats });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Get all users
const getAllUsers = async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json({ success: true, data: users });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Update user role
const updateUserRole = async (req, res) => {
  try {
    const { role } = req.body;
    const user = await User.findByIdAndUpdate( 
      req.params.id,
      { role },
      { new: true }
    ).select('-password');

    res.json({ success: true, data: user });
  } catch (err) {
    res.status(400).json({ success: false, message: 'Update failed' });
  }
};

module.exports = {
  getDashboardStats,
  getAllUsers,
  updateUserRole,
};
