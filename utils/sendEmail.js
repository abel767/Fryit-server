const nodemailer = require('nodemailer')
const {google} = require('googlepis')

// 0auth2 client setup (recommended for gmail) 
const oAuth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_0AUTH_CLIENT_ID,
    process.env.GOOGLE_0AUTH_CLIENT_SECRET, 
    process.env.GOOGLE_0AUTH_REDIRECT_URI
)

oAuth2Client.setCredentials({refresh_token: process.env.GOOGLE_OAUTH_REFRESH_TOKEN})

const sendEmail = async (options)=>{
    try{
        const accessToken = await oAuth2Client.getAccessToken()

        const transport = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                type: 'OAuth2',
                user: process.env.GOOGLE_OAUTH_CLIENT_ID,
                clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
                refreshToken: process.env.GOOGLE_OAUTH_REFRESH_TOKEN,
                accessToken: accessToken.token
            }
        })

        const mailOptions = {
            from: `IndieVerse <${process.env.SMTP_EMAIL}>`,
            to: options.email,
            subject: options.subject,
            html: options.html
        }

        await transport.sendMail(mailOptions)
    }catch(err){
        console.error('Email send error:', err)
        throw new Error('Email could not be sent')
    }
}

module.exports = sendEmail