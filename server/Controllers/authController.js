const getConnection = require('../Models/database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


const { sendOtpEmail } = require('../Utility/mail');

const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;

const registerUser = async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Please provide username, email, and password.' });
    }

    let conn;
    try {
        conn = await getConnection();

        // The result from the query IS the array of rows.
        const rows = await conn.query("SELECT email FROM techcoach_lite.techcoach_users WHERE email = ? AND is_verified = 1", [email]);
        
        // This check will now work correctly.
        if (rows.length > 0) {
            return res.status(409).json({ message: 'A verified user with this email already exists.' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(new Date().getTime() + 10 * 60 * 1000);

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        
        await conn.query(
            `INSERT INTO techcoach_lite.techcoach_users (displayName, username, email, password_hash, login_provider, otp, otp_expires, is_verified) 
             VALUES (?, ?, ?, ?, 'local', ?, ?, 0)
             ON DUPLICATE KEY UPDATE 
             password_hash = VALUES(password_hash), otp = VALUES(otp), otp_expires = VALUES(otp_expires), is_verified = 0`,
            [username, username, email, passwordHash, otp, otpExpires]
        );

        await sendOtpEmail(email, otp);

        res.status(200).json({ message: 'OTP has been sent to your email address. Please verify to complete registration.' });

    } catch (error) {
        console.error('Error during registration initiation:', error);
        res.status(500).json({ error: 'An error occurred during registration.' });
    } finally {
        if (conn) conn.release();
    }
};

const verifyOtp = async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({ message: 'Please provide both email and OTP.' });
    }

    let conn;
    try {
        conn = await getConnection();

        // The result from the query IS the array of rows.
        const rows = await conn.query("SELECT * FROM techcoach_lite.techcoach_users WHERE email = ?", [email]);

        // This check will now work correctly.
        if (!rows || rows.length === 0) {
            return res.status(404).json({ message: 'User not found or registration not initiated.' });
        }
        
        // Get the user object directly from the first element of the rows array.
        const user = rows[0];

        if (user.is_verified) {
            return res.status(400).json({ message: 'This account is already verified.' });
        }

        if (user.otp !== otp || new Date() > new Date(user.otp_expires)) {
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }
        
        await conn.query("UPDATE techcoach_lite.techcoach_users SET is_verified = 1, otp = NULL, otp_expires = NULL WHERE user_id = ?", [user.user_id]);

        const payload = { id: user.user_id, email: user.email };
        const token = jwt.sign(payload, JWT_SECRET_KEY, { expiresIn: '24h' });

        res.status(200).json({
            message: 'Account verified successfully! You are now logged in.',
            token: token
        });

    } catch (error) {
        console.error('Error during OTP verification:', error);
        res.status(500).json({ error: 'An error occurred during verification.' });
    } finally {
        if (conn) conn.release();
    }
};

const loginUser = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Please provide email and password.' });
    }

    let conn;
    try {
        conn = await getConnection();

        // --- START OF THE FIX ---
        // The result from the query IS the array of rows.
        const rows = await conn.query("SELECT * FROM techcoach_lite.techcoach_users WHERE email = ?", [email]);

        // This check will now work correctly.
        if (!rows || rows.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }
        
        // Get the user object directly from the first element of the rows array.
        const user = rows[0];
        // --- END OF THE FIX ---

        if (!user.is_verified) {
             return res.status(403).json({ message: 'Account not verified. Please check your email for an OTP.' });
        }

        if (user.login_provider !== 'local') {
            return res.status(403).json({ message: `This account uses Google login. Please sign in with Google.` });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const payload = { id: user.user_id, email: user.email };
        const token = jwt.sign(payload, JWT_SECRET_KEY, { expiresIn: '24h' });

        res.status(200).json({
            message: 'Login successful!',
            token: token
        });

    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'An error occurred during login.' });
    } finally {
        if (conn) conn.release();
    }
};


// You only need to export the new functions
module.exports = { registerUser, loginUser, verifyOtp };