const mongoose = require('mongoose')
const bcrypt = require('bcrypt')

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minLength: true,
        minLength: 3,
        maxLength: 30
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
    },
    password: {
        type: String,
        minlength: 6,
        select: false
    },
    role: {
        type: String,
        enum: ['admin', 'developer', 'user'],
        default: 'user'
    },
    avatar: {
        type: String,
        default: 'https://res.cloudinary.com/your-cloud-name/image/upload/v1620000000/default-avatar.png'
    },
    isVerified: {
        type: Boolean,
        default: false,
    },
    verificationCode: {
        type: String,
        select: false,
    },
    verificationCodeExpires: {
        type: Date,
        select: false,
    },
    resetPasswordToken: {
        type: String,
        select: false
    },
    resetPasswordExpire: {
        type: Date,
        select: false
    },
    refreshToken: {
        type: String,
        select: false,
    },
    refreshTokenExpires: {
        type: Date,
        select: false
    }
},
{
    timestamps: true
}
)


UserSchema.pre('save', async function (next) {
    if(!this.isModified('password')) return next()

        this.password = await bcrypt.hash(this.password, 12)
        next()
})


// methods to compare passwords
UserSchema.methods.comparePasswords = async function (candidatePassword){
    return await bcrypt.compare(candidatePassword, this.password)
}

module.exports = mongoose.model('User', UserSchema)