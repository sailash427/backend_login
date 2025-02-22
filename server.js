const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(bodyParser.json());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000', // Allow only your front-end URL
    optionsSuccessStatus: 200
}));

// Rate limiting for sensitive endpoints
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // Limit each IP to 100 requests per windowMs
});
app.use('/api/users/login', limiter);
app.use('/api/users/forgot-password', limiter);

// Configure the email transporter
const transporter = nodemailer.createTransport({
    service: 'Gmail', // You can use any email service
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    // Add the following timeout settings
    socketTimeout: 60000, // Increase timeout to 60 seconds
    connectionTimeout: 60000 // Increase connection timeout to 60 seconds
});

// Function to send the password reset email
const sendPasswordResetEmail = (email, token) => {
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`; // Frontend URL
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Password Reset Request',
        text: `You requested a password reset. Click the link below to reset your password:\n\n${resetUrl}\n\nIf you did not request this, please ignore this email.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Error sending password reset email:', error);
        } else {
            console.log('Password reset email sent:', info.response);
        }
    });
};

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
    useUnifiedTopology: true,
    useNewUrlParser: true
})
    .then(() => console.log('MongoDB connected...'))
    .catch(err => console.error('MongoDB connection error:', err));

// User Schema and Model
const userSchema = new mongoose.Schema({
    FirstName: String,
    MiddleName: String,
    LastName: String,
    Role: String,
    Gender: String,
    Nationality: String,
    State: String,
    Pincode: String,
    Email: { type: String, unique: true },
    Password: String
});

// Password Hashing Middleware
userSchema.pre('save', async function (next) {
   if (!this.isModified('Password')) {
       return next();
   }
   try {
       const salt = await bcrypt.genSalt(10);
       this.Password = await bcrypt.hash(this.Password, salt);
       next();
   } catch (err) {
       next(err);
   }
});

const User = mongoose.model('User', userSchema);

// Generate JWT Token
const generateToken = (user) => {
    return jwt.sign({ id: user._id, email: user.Email }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

// Routes

/**
 * @route POST /api/users
 * @desc Create a new user
 */
app.post('/api/users', async (req, res) => {
    try {
        console.log('Received request to create user:', req.body);

        // Check if the email already exists
        const existingUser = await User.findOne({ Email: req.body.Email });
        if (existingUser) {
            console.log('Email already exists:', req.body.Email);
            return res.status(400).send({ error: "Email already exists" });
        }

        // Create a new user
        const user = new User(req.body);
        await user.save();
        console.log('User created successfully:', user);
        res.status(201).send(user);
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(400).send({ error: 'Failed to create user', details: error.message });
    }
});

/**
 * @route POST /api/users/login
 * @desc Login a user
 */
app.post('/api/users/login', async (req, res) => {
    try {
        const { Email, Password } = req.body;
        console.log('Received login request:', req.body);

        // Check if the user exists
        const user = await User.findOne({ Email });
        if (!user) {
            console.log('Email does not exist:', Email);
            return res.status(400).send({ error: "Invalid email or password" });
        }

        // Check if the password matches
        const isMatch = await bcrypt.compare(Password, user.Password);
        if (!isMatch) {
            console.log('Invalid password for email:', Email);
            return res.status(400).send({ error: "Invalid email or password" });
        }

        // Generate JWT token
        const token = generateToken(user);
        console.log('User logged in successfully:', user);
        res.status(200).send({ user, token });
    } catch (error) {
        console.error('Error logging in user:', error);
        res.status(500).send({ error: 'Failed to login', details: error.message });
    }
});

/**
 * @route GET /api/users/check-email
 * @desc Check if an email already exists
 */
app.get('/api/users/check-email', async (req, res) => {
    try {
        const email = req.query.email;
        console.log('Checking if email exists:', email);

        if (!email) {
            return res.status(400).send({ error: "Email is required" });
        }

        const existingUser = await User.findOne({ Email: email });
        res.send({ exists: !!existingUser });
    } catch (error) {
        console.error('Error checking email:', error);
        res.status(500).send({ error: 'Failed to check email', details: error.message });
    }
});

/**
 * @route GET /api/users/:email
 * @desc Get user data by email
 */
app.get('/api/users/:email', async (req, res) => {
    try {
        const email = req.params.email;
        console.log('Fetching user data for email:', email);

        // Find the user by email
        const user = await User.findOne({ Email: email });
        if (!user) {
            return res.status(404).send({ error: "User not found" });
        }

        console.log('User data retrieved successfully:', user);
        res.status(200).send(user);
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).send({ error: 'Failed to fetch user data', details: error.message });
    }
});

/**
 * @route POST /api/users/forgot-password
 * @desc Send a password reset link to the user's email
 */
app.post('/api/users/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        console.log('Received forgot password request for email:', email);

        // Check if the user exists
        const user = await User.findOne({ Email: email });
        if (!user) {
            console.log('Email does not exist:', email);
            return res.status(400).send({ error: "Email not found" });
        }

        // Generate a password reset token
        const resetToken = jwt.sign({ email: user.Email }, process.env.JWT_SECRET, { expiresIn: '15m' });

        // Send the reset token to the user's email
        sendPasswordResetEmail(user.Email, resetToken);

        res.status(200).send({ message: "Password reset link sent to your email." });
    } catch (error) {
        console.error('Error handling forgot password:', error);
        res.status(500).send({ error: 'Failed to process forgot password request', details: error.message });
    }
});

/**
 * @route POST /api/users/reset-password
 * @desc Reset user password using the token
 */
app.post('/api/users/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        // Verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log('Decoded token:', decoded);

        // Find the user
        const user = await User.findOne({ Email: decoded.email });
        console.log('User found:', user);

        if (!user) {
            return res.status(400).send({ error: "Invalid or expired token" });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        user.Password = await bcrypt.hash(newPassword, salt);
        console.log('Hashed password:', user.Password);

        // Save the updated user
        await user.save();
        console.log('User saved successfully');

        res.status(200).send({ message: "Password reset successfully" });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).send({ error: 'Failed to reset password', details: error.message });
    }
});

// Centralized error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send({ error: 'Something went wrong!' });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
