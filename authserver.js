// authserver.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

// Configuration
const PORT = process.env.PORT || 5001;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Initialize Express
const app = express();
app.use(express.json());
app.use(cors());

// Request Logging Middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] Incoming request: ${req.method} ${req.url}`);
  console.log('Request headers:', req.headers);
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('Request body:', req.body);
  }
  next(); // Move on to the next middleware or route handler
});

// Connect to MongoDB
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('Failed to connect to MongoDB', err));

// Define User Schema and Model
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

userSchema.index({ email: 1 }); // Index on email field for faster lookup
const User = mongoose.model('User', userSchema);

// Routes
app.get('/', (req, res) => {
  console.log('API Gateway has reached the root endpoint');
  res.status(200).json({ message: 'twitter-Auth Service is up and running!' });
});

// Register a new user
app.post('/api/auth/register', async (req, res) => {
  console.log('API Gateway is forwarding a registration request');
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    console.log('User registered successfully:', email);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error during registration:', error.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// authserver.js

app.post('/api/auth/login', async (req, res) => {
  console.log(`[Auth Service] Request received from API Gateway: ${req.method} ${req.url}`);
  console.log('Request Body:', req.body);
  console.log('Request Headers:', req.headers);

  const startTime = Date.now();

  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    console.log(`User.findOne() took ${Date.now() - startTime} ms`);

    if (!user) {
      console.log('[Auth Service] Login failed: User not found');
      return res.status(404).json({ error: 'User not found' });
    }

    const passwordCheckStart = Date.now();
    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log(`bcrypt.compare() took ${Date.now() - passwordCheckStart} ms`);

    if (!isPasswordValid) {
      console.log('[Auth Service] Login failed: Invalid credentials');
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    console.log('[Auth Service] Login successful for user:', email);
    console.log(`[Auth Service] Total time for login: ${Date.now() - startTime} ms`);

    res.status(200).json({ token });
  } catch (error) {
    console.error('[Auth Service] Error during login:', error.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Auth Service running on port ${PORT}`);
});
