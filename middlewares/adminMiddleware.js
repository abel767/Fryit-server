const {authorize} = require('./authMiddleware')

// Specifically for admin-only routes
exports.adminOnly = authorize('admin')
