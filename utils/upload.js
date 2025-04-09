const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary'); // Fixed import
const multer = require('multer');

// Config cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY, // Added missing KEY
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'indieverse/avatars',
        allowed_formats: ['jpg', 'jpeg', 'png', 'gif'],
        transformation: [{ width: 500, height: 500, crop: 'limit' }]
    }
});

const upload = multer({
    storage: storage, // Fixed: Storage -> storage
    limits: { fileSize: 5 * 1024 * 1024 }, // Fixed: filesize -> fileSize
    fileFilter: (req, file, cb) => {
        if(file.mimetype.startsWith('image/')) { // Fixed: starrtsWith -> startsWith
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'), false); // Fixed: area -> are
        }
    }
});

module.exports = upload; // Export directly, not as an object