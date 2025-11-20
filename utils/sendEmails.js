const { SESClient, SendEmailCommand } = require("@aws-sdk/client-ses")
const nodemailer = require("nodemailer")

// const transporter = nodemailer.createTransport({
//     host: process.env.MAILTRAP_HOST,
//     port: process.env.MAILTRAP_PORT,
//     secure: false, // Mailtrap often uses STARTTLS on port 2525/587, so this is false
//     auth: {
//       user: process.env.MAILTRAP_USERNAME,
//       pass: process.env.MAILTRAP_PASSWORD,
//     },
// })

const brevoTransporter = nodemailer.createTransport({
    host: process.env.BREVO_SMTP_SERVER,
    port: process.env.BREVO_SMTP_PORT,
    secure: false, // Mailtrap often uses STARTTLS on port 2525/587, so this is false
    auth: {
      user: process.env.BREVO_SMTP_LOGIN,
      pass: process.env.BREVO_SMTP_KEY,
    },
})


const sendVerificationLink = async (to , subject , body) => {
    console.log('sendign email')

    try {
        const info = await brevoTransporter.sendMail({
            from : 'Super stuff<ogounainehamza@gmail.com>',
            to : to,
            subject : subject,
            html : body
        })
        console.log('Email has been sent' , info)
        return true
    }
    catch (err) {
        console.log('Error sending mail' , err)
        return false
    }

}


// const REGION =  'us-east-1'; // Use AWS_REGION env var
// const SOURCE_EMAIL = 'support@superstuff.online'; 
// const defTextBody = `Welcome to SuperStuff! Click this link to verify your account: http://yourdomain.com/verify/token`;

// // 💡 FIX: Initialize the client without hardcoding credentials.
// // The SDK will securely load them from the environment or IAM role.
// const sesClient = new SESClient({
//     region : REGION,
//     // REMOVED: credentials object
// }); 


// const sendVerificationLink = async (to , subject , htmlBody , textBody=defTextBody) => {
//     const params = {
//         Source: 'support@superstuff.online',
//         Destination: {
//             ToAddresses: [to],
//         },
//         Message: {
//             Subject: {
//                 Charset: "UTF-8",
//                 Data: subject,
//             },
//             Body: {
//                 Html: { // Crucial for rich formatting
//                     Charset: "UTF-8",
//                     Data: htmlBody,
//                 },
//                 Text: { // Non-negotiable for deliverability/spam filters
//                     Charset: "UTF-8",
//                     Data: textBody, 
//                 },
//             },
//         },
//     };
        
        
//     const command = new SendEmailCommand(params)

//     try {
//         const res = await sesClient.send(command)
//         console.log('✅ Email sent successfully. Message ID:', res.MessageId);
//         return true;
//     }
//     catch(err) {
//         console.error('❌ Error sending mail via SES SDK:', err); 
//         return false;
//     }
// }


module.exports = {sendVerificationLink}