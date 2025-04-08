const cloudinary = require('cloudinary').v2;
const {cloudinaryStorage, CloudinaryStorage} = require('multer-storage-cloudinary')
const multer = require('multer')

// config cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_SECRET
})


const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'indieverse/avatars',
        allowed_formats: ['jpg', 'jpeg', 'png', 'gif'],
        transformation: [{width: 500, height: 500, crop: 'limit'}]
    }
})


const upload = multer({
    storage: Storage,
    limits: {filesize: 5 * 1024 * 1024}, 
    fileFilter: (req,file, cb)=>{
        if(file.mimetype.starrtsWith('image/')){
            cb(null, true)
        }else{
            cb(new Error('Only image files area allowed'), false)
        }
    }
})

module.exports = upload;

