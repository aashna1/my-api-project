// JWT Authentication System
// Required packages:
// npm install express jsonwebtoken bcrypt dotenv

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
app.use(express.json());

// In a real application, you would use a database
// This is a simple in-memory user store for demonstration
const users = [];

// Environment variables (store these in a .env file)
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';
const PORT = process.env.PORT || 3000;
const TOKEN_EXPIRY = '24h';

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN format
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Refresh token store (in production, use Redis or a database)
const refreshTokens = new Set();

// User Registration Route
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Check if user already exists
    if (users.some(user => user.email === email)) {
      return res.status(409).json({ error: 'User already exists' });
    }
    
    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create new user
    const newUser = {
      id: users.length + 1,
      username,
      email,
      password: hashedPassword
    };
    
    users.push(newUser);
    
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// User Login Route
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const user = users.find(user => user.email === email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Validate password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Create tokens
    const accessToken = generateAccessToken(user);
    const refreshToken = jwt.sign({ id: user.id }, JWT_SECRET);
    
    // Store refresh token
    refreshTokens.add(refreshToken);
    
    res.json({
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Refresh Token Route
app.post('/api/token/refresh', (req, res) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token required' });
  }
  
  // Check if refresh token exists in our store
  if (!refreshTokens.has(refreshToken)) {
    return res.status(403).json({ error: 'Invalid refresh token' });
  }
  
  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    
    // Find user
    const user = users.find(user => user.id === decoded.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Generate new access token
    const accessToken = generateAccessToken(user);
    
    res.json({ accessToken });
  } catch (error) {
    res.status(403).json({ error: 'Invalid refresh token' });
  }
});

// Logout Route
app.post('/api/logout', (req, res) => {
  const { refreshToken } = req.body;
  
  // Remove refresh token from store
  refreshTokens.delete(refreshToken);
  
  res.json({ message: 'Logged out successfully' });
});

// Protected Route Example
app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({
    message: 'Protected data accessed successfully',
    user: req.user
  });
});

// User Profile Route
app.get('/api/profile', authenticateToken, (req, res) => {
  const user = users.find(user => user.id === req.user.id);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  res.json({
    id: user.id,
    username: user.username,
    email: user.email
  });
});

// Change Password Route
app.put('/api/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    // Find user
    const userIndex = users.findIndex(user => user.id === req.user.id);
    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = users[userIndex];
    
    // Validate current password
    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    
    // Update password
    users[userIndex].password = hashedPassword;
    
    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Helper function to generate access token
function generateAccessToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email }, 
    JWT_SECRET, 
    { expiresIn: TOKEN_EXPIRY }
  );
}

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Example .env file contents:
/*
JWT_SECRET=your_super_secure_secret_key_here
PORT=3000
*/