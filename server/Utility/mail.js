require('dotenv').config();
const axios = require('axios');

async function sendWelcomeEmail(user) {
    if (Array.isArray(user) && user.length > 0) {
        for (const singleUser of user) {
            const { email, displayname, logintime } = singleUser;

            const emailPayload = {
                from: {
                    address: "Decision-Coach@www.careersheets.in",
                    name: "Techcoach Lite"
                },
                to: [
                    {
                        email_address: {
                            address: process.env.USER_EMAILNAME
                        }
                    }
                ],
                subject: "New User Added Techcoach_lite(Decision_APP)",
                htmlbody: `
                    <p><strong>Name:</strong> ${displayname}</p>
                    <p><strong>Email:</strong> ${email}</p>
                    <p><strong>Login Time:</strong> ${logintime}</p>
                `
            };

            const zeptoMailApiUrl = 'https://api.zeptomail.in/v1.1/email';
            const zeptoMailApiKey = process.env.ZEPTO_MAIL_API_KEY;

            try {
                await axios.post(zeptoMailApiUrl, emailPayload, {
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Zoho-enczapikey ${zeptoMailApiKey}`
                    }
                });
                console.log(`Email sent to ${displayname}`);
            } catch (error) {
                console.error(`Failed to send email to ${displayname}:`, error.response?.data || error.message);
            }
        }
    } else {
        console.error("User data is not in the expected format.");
    }
}

module.exports = sendWelcomeEmail;
