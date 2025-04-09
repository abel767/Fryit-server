const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
    try {
        // Create SMTP transporter
        const transport = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: process.env.SMTP_PORT,
            secure: false, // true for 465, false for other ports
            auth: {
                user: process.env.SMTP_EMAIL,
                pass: process.env.SMTP_PASSWORD
            }
        });

        const mailOptions = {
            from: `${process.env.FROM_NAME} <${process.env.FROM_EMAIL || process.env.SMTP_EMAIL}>`,
            to: options.email,
            subject: options.subject,
            html: options.html
        };

        await transport.sendMail(mailOptions);
    } catch(err) {
        console.error('Email send error:', err);
        throw new Error('Email could not be sent');
    }
};

module.exports = sendEmail;