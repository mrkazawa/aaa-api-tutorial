# Part 2: Username & Password Login with JWT

## Learning Objectives

By the end of this part, you will:
- ✅ Understand password hashing with bcrypt
- ✅ Implement user registration with secure password storage
- ✅ Create login endpoint with credential validation
- ✅ Generate and validate JWT access tokens
- ✅ Implement refresh token mechanism
- ✅ Track login attempts for security
- ✅ Implement account lockout after failed attempts

## Overview

In Part 2, we'll add **Authentication** - the first "A" in AAA security. We'll implement a complete username/password authentication system with JWT (JSON Web Tokens) for stateless session management.

## Security Concepts Covered

### 1. Password Hashing
- Never store plain text passwords
- Use bcrypt with salt rounds
- One-way hashing (cannot be reversed)

### 2. JWT (JSON Web Tokens)
- Stateless authentication
- Access tokens (short-lived: 15 minutes)
- Refresh tokens (long-lived: 7 days)
- Token-based authorization

### 3. Security Monitoring
- Track all login attempts
- Lock account after 3 failed attempts
- Store IP address and user agent

## Architecture

```
┌─────────────────────────────────────────────────┐
│                Client Request                    │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
    ┌────────────────────────┐
    │  POST /api/auth/login  │
    │  { username, password }│
    └───────────┬────────────┘
                │
                ▼
    ┌────────────────────────┐
    │  Validate Credentials  │
    │  - Find user           │
    │  - Compare password    │
    │  - Check lockout       │
    └───────────┬────────────┘
                │
        ┌───────┴───────┐
        │               │
    Success          Failure
        │               │
        ▼               ▼
    ┌───────┐      ┌────────────┐
    │  JWT  │      │ Log attempt│
    │ Token │      │ Check count│
    │       │      │ Lock if ≥3 │
    └───────┘      └────────────┘
```

## Step 1: Install Required Dependencies

### Create new directories

First, create the directories we'll need for this part:

```bash
mkdir -p api/src/utils
mkdir -p api/src/services
mkdir -p api/src/middleware
```

Update `api/package.json`:

```json
{
  "name": "banking-api",
  "version": "1.0.0",
  "description": "Simple Banking API for AAA Security Education",
  "main": "src/server.js",
  "scripts": {
    "dev": "nodemon src/server.js",
    "start": "node src/server.js"
  },
  "keywords": ["banking", "api", "security", "aaa", "education"],
  "author": "Your Name",
  "license": "MIT",
  "dependencies": {
    "express": "^4.18.2",
    "mysql2": "^3.6.5",
    "dotenv": "^16.3.1",
    "cors": "^2.8.5",
    "helmet": "^7.1.0",
    "bcrypt": "^5.1.1",
    "jsonwebtoken": "^9.0.2",
    "express-validator": "^7.0.1",
    "cookie-parser": "^1.4.6"
  },
  "devDependencies": {
    "nodemon": "^3.0.2"
  }
}
```

Rebuild the container to install new dependencies:

```bash
# Stop containers
docker-compose down

# Rebuild with new dependencies
docker-compose up --build -d

# Check logs to ensure no errors
docker-compose logs -f api
```

**Important:** Wait for the container to fully start before proceeding. You should see "✅ Database connected successfully" in the logs.

## Step 2: Create Utility Functions

### `api/src/utils/hashPassword.js`

```javascript
const bcrypt = require('bcrypt');

const SALT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 10;

/**
 * Hash a plain text password
 * @param {string} password - Plain text password
 * @returns {Promise<string>} - Hashed password
 */
exports.hashPassword = async (password) => {
  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    return hash;
  } catch (error) {
    throw new Error('Error hashing password');
  }
};

/**
 * Compare plain text password with hashed password
 * @param {string} password - Plain text password
 * @param {string} hash - Hashed password
 * @returns {Promise<boolean>} - True if match
 */
exports.comparePassword = async (password, hash) => {
  try {
    const match = await bcrypt.compare(password, hash);
    return match;
  } catch (error) {
    throw new Error('Error comparing passwords');
  }
};
```

### `api/src/utils/validators.js`

```javascript
const { body, validationResult } = require('express-validator');

/**
 * Validation rules for user registration
 */
exports.registerValidation = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage('Username must be 3-50 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  
  body('email')
    .trim()
    .isEmail()
    .withMessage('Must be a valid email')
    .normalizeEmail(),
  
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
  
  body('first_name')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be 1-50 characters'),
  
  body('last_name')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be 1-50 characters'),
  
  body('phone')
    .optional()
    .trim()
    .matches(/^\+?[\d\s-()]+$/)
    .withMessage('Invalid phone number format')
];

/**
 * Validation rules for login
 */
exports.loginValidation = [
  body('username')
    .trim()
    .notEmpty()
    .withMessage('Username is required'),
  
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

/**
 * Middleware to check validation results
 */
exports.validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array()
    });
  }
  next();
};
```

## Step 3: Create Token Service

### `api/src/services/tokenService.js`

```javascript
const jwt = require('jsonwebtoken');
const db = require('../config/database');
const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRATION = process.env.JWT_EXPIRATION || '15m';
const REFRESH_TOKEN_EXPIRATION = process.env.REFRESH_TOKEN_EXPIRATION || '7d';

/**
 * Generate JWT access token
 * @param {object} user - User object
 * @returns {string} - JWT token
 */
exports.generateAccessToken = (user) => {
  const payload = {
    id: user.id,
    username: user.username,
    email: user.email
  };
  
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRATION,
    issuer: 'banking-api',
    subject: user.id.toString()
  });
};

/**
 * Generate refresh token and store in database
 * @param {number} userId - User ID
 * @returns {Promise<string>} - Refresh token
 */
exports.generateRefreshToken = async (userId) => {
  // Generate random token
  const token = crypto.randomBytes(64).toString('hex');
  
  // Calculate expiration
  const expiresAt = new Date();
  const days = parseInt(REFRESH_TOKEN_EXPIRATION) || 7;
  expiresAt.setDate(expiresAt.getDate() + days);
  
  // Store in database
  await db.query(
    'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
    [userId, token, expiresAt]
  );
  
  return token;
};

/**
 * Verify JWT access token
 * @param {string} token - JWT token
 * @returns {object} - Decoded token payload
 */
exports.verifyAccessToken = (token) => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded;
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new Error('Token expired');
    } else if (error.name === 'JsonWebTokenError') {
      throw new Error('Invalid token');
    } else {
      throw new Error('Token verification failed');
    }
  }
};

/**
 * Verify refresh token from database
 * @param {string} token - Refresh token
 * @returns {Promise<object|null>} - User info if valid
 */
exports.verifyRefreshToken = async (token) => {
  const [rows] = await db.query(
    `SELECT rt.*, u.id, u.username, u.email, u.is_active
     FROM refresh_tokens rt
     JOIN users u ON rt.user_id = u.id
     WHERE rt.token = ? 
       AND rt.expires_at > NOW() 
       AND rt.revoked = FALSE
       AND u.is_active = TRUE`,
    [token]
  );
  
  if (rows.length === 0) {
    return null;
  }
  
  return {
    id: rows[0].id,
    username: rows[0].username,
    email: rows[0].email
  };
};

/**
 * Revoke refresh token
 * @param {string} token - Refresh token
 */
exports.revokeRefreshToken = async (token) => {
  await db.query(
    'UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW() WHERE token = ?',
    [token]
  );
};

/**
 * Revoke all refresh tokens for a user
 * @param {number} userId - User ID
 */
exports.revokeAllUserTokens = async (userId) => {
  await db.query(
    'UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW() WHERE user_id = ? AND revoked = FALSE',
    [userId]
  );
};

/**
 * Clean up expired tokens (call periodically)
 */
exports.cleanupExpiredTokens = async () => {
  await db.query('DELETE FROM refresh_tokens WHERE expires_at < NOW()');
};
```

## Step 4: Create Authentication Service

### `api/src/services/authService.js`

```javascript
const db = require('../config/database');
const { hashPassword, comparePassword } = require('../utils/hashPassword');

const MAX_LOGIN_ATTEMPTS = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 3;
const LOCKOUT_DURATION_MINUTES = parseInt(process.env.ACCOUNT_LOCKOUT_DURATION_MINUTES) || 15;

/**
 * Create a new user
 * @param {object} userData - User registration data
 * @returns {Promise<object>} - Created user
 */
exports.createUser = async (userData) => {
  const { username, email, password, first_name, last_name, phone } = userData;
  
  // Check if user already exists
  const [existing] = await db.query(
    'SELECT id FROM users WHERE username = ? OR email = ?',
    [username, email]
  );
  
  if (existing.length > 0) {
    throw new Error('Username or email already exists');
  }
  
  // Hash password
  const password_hash = await hashPassword(password);
  
  // Insert user
  const [result] = await db.query(
    `INSERT INTO users (username, email, password_hash, first_name, last_name, phone, auth_provider) 
     VALUES (?, ?, ?, ?, ?, ?, 'local')`,
    [username, email, password_hash, first_name || null, last_name || null, phone || null]
  );
  
  // Assign default 'customer' role
  const [roleResult] = await db.query('SELECT id FROM roles WHERE name = ?', ['customer']);
  if (roleResult.length > 0) {
    await db.query(
      'INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)',
      [result.insertId, roleResult[0].id]
    );
  }
  
  // Return user without password
  const [newUser] = await db.query(
    'SELECT id, username, email, first_name, last_name, phone, created_at FROM users WHERE id = ?',
    [result.insertId]
  );
  
  return newUser[0];
};

/**
 * Find user by username
 * @param {string} username - Username
 * @returns {Promise<object|null>} - User object or null
 */
exports.findUserByUsername = async (username) => {
  const [rows] = await db.query(
    'SELECT * FROM users WHERE username = ? AND is_active = TRUE',
    [username]
  );
  
  return rows.length > 0 ? rows[0] : null;
};

/**
 * Find user by ID
 * @param {number} userId - User ID
 * @returns {Promise<object|null>} - User object or null
 */
exports.findUserById = async (userId) => {
  const [rows] = await db.query(
    'SELECT id, username, email, first_name, last_name, phone, auth_provider, created_at, last_login_at FROM users WHERE id = ? AND is_active = TRUE',
    [userId]
  );
  
  return rows.length > 0 ? rows[0] : null;
};

/**
 * Verify user credentials
 * @param {string} username - Username
 * @param {string} password - Password
 * @returns {Promise<object|null>} - User object if valid, null otherwise
 */
exports.verifyCredentials = async (username, password) => {
  const user = await exports.findUserByUsername(username);
  
  if (!user || !user.password_hash) {
    return null;
  }
  
  const isValid = await comparePassword(password, user.password_hash);
  
  if (!isValid) {
    return null;
  }
  
  // Remove password hash from returned object
  delete user.password_hash;
  return user;
};

/**
 * Verify password against hash
 * @param {string} password - Plain text password
 * @param {string} hash - Password hash
 * @returns {Promise<boolean>} - True if password matches
 */
exports.verifyPassword = async (password, hash) => {
  if (!hash) {
    return false;
  }
  return await comparePassword(password, hash);
};

/**
 * Log login attempt
 * @param {string} username - Username
 * @param {string} ipAddress - IP address
 * @param {string} userAgent - User agent
 * @param {boolean} success - Whether login was successful
 * @param {string} failureReason - Reason for failure (if applicable)
 */
exports.logLoginAttempt = async (username, ipAddress, userAgent, success, failureReason = null) => {
  await db.query(
    `INSERT INTO login_attempts (username, ip_address, user_agent, success, failure_reason) 
     VALUES (?, ?, ?, ?, ?)`,
    [username, ipAddress, userAgent, success, failureReason]
  );
};

/**
 * Check if account is locked
 * @param {string} username - Username
 * @returns {Promise<boolean>} - True if locked
 */
exports.isAccountLocked = async (username) => {
  const [rows] = await db.query(
    `SELECT al.* FROM account_lockouts al
     JOIN users u ON al.user_id = u.id
     WHERE u.username = ? 
       AND al.unlock_at > NOW()
       AND al.is_unlocked = FALSE
     ORDER BY al.locked_at DESC
     LIMIT 1`,
    [username]
  );
  
  return rows.length > 0;
};

/**
 * Get recent failed login attempts
 * @param {string} username - Username
 * @param {number} minutes - Time window in minutes
 * @returns {Promise<number>} - Count of failed attempts
 */
exports.getRecentFailedAttempts = async (username, minutes = 15) => {
  const [rows] = await db.query(
    `SELECT COUNT(*) as count FROM login_attempts 
     WHERE username = ? 
       AND success = FALSE 
       AND attempted_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)`,
    [username, minutes]
  );
  
  return rows[0].count;
};

/**
 * Lock user account
 * @param {number} userId - User ID
 * @param {string} reason - Reason for lockout
 */
exports.lockAccount = async (userId, reason = 'Multiple failed login attempts') => {
  const unlockAt = new Date();
  unlockAt.setMinutes(unlockAt.getMinutes() + LOCKOUT_DURATION_MINUTES);
  
  await db.query(
    `INSERT INTO account_lockouts (user_id, unlock_at, reason) 
     VALUES (?, ?, ?)`,
    [userId, unlockAt, reason]
  );
};

/**
 * Update last login time
 * @param {number} userId - User ID
 */
exports.updateLastLogin = async (userId) => {
  await db.query(
    'UPDATE users SET last_login_at = NOW() WHERE id = ?',
    [userId]
  );
};

/**
 * Get user with roles
 * @param {number} userId - User ID
 * @returns {Promise<object>} - User with roles array
 */
exports.getUserWithRoles = async (userId) => {
  const user = await exports.findUserById(userId);
  
  if (!user) {
    return null;
  }
  
  // Get user roles
  const [roles] = await db.query(
    `SELECT r.id, r.name, r.description 
     FROM roles r
     JOIN user_roles ur ON r.id = ur.role_id
     WHERE ur.user_id = ?`,
    [userId]
  );
  
  user.roles = roles.map(r => r.name);
  
  return user;
};
```

## Step 5: Create Authentication Controller

### `api/src/controllers/authController.js`

```javascript
const authService = require('../services/authService');
const tokenService = require('../services/tokenService');

/**
 * Register a new user
 * POST /api/auth/register
 */
exports.register = async (req, res) => {
  try {
    const { username, email, password, first_name, last_name, phone } = req.body;
    
    // Create user
    const user = await authService.createUser({
      username,
      email,
      password,
      first_name,
      last_name,
      phone
    });
    
    console.log(`✅ New user registered: ${username}`);
    
    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Registration error:', error.message);
    
    if (error.message.includes('already exists')) {
      return res.status(409).json({ error: error.message });
    }
    
    res.status(500).json({ error: 'Registration failed' });
  }
};

/**
 * Login with username and password
 * POST /api/auth/login
 */
exports.login = async (req, res) => {
  try {
    const { username, password } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('user-agent') || 'unknown';
    
    // Step 1: Check if user exists
    const user = await authService.findUserByUsername(username);
    
    if (!user) {
      // Don't reveal that user doesn't exist - use generic error
      await authService.logLoginAttempt(username, ipAddress, userAgent, false, 'user_not_found');
      return res.status(401).json({
        error: 'Invalid username or password'
      });
    }
    
    // Step 2: Check if account is locked
    const isLocked = await authService.isAccountLocked(username);
    if (isLocked) {
      await authService.logLoginAttempt(username, ipAddress, userAgent, false, 'account_locked');
      return res.status(423).json({
        error: 'Account is locked due to multiple failed login attempts',
        message: `Please try again in ${process.env.ACCOUNT_LOCKOUT_DURATION_MINUTES || 15} minutes`
      });
    }
    
    // Step 3: Verify password
    const isValidPassword = await authService.verifyPassword(password, user.password_hash);
    
    if (!isValidPassword) {
      // Log failed attempt
      await authService.logLoginAttempt(username, ipAddress, userAgent, false, 'invalid_password');
      
      // Check if should lock account
      const failedAttempts = await authService.getRecentFailedAttempts(username, 15);
      
      if (failedAttempts >= parseInt(process.env.MAX_LOGIN_ATTEMPTS || 3)) {
        // Lock the account
        await authService.lockAccount(user.id);
        console.log(`🔒 Account locked: ${username} (${failedAttempts} failed attempts)`);
        
        return res.status(423).json({
          error: 'Account locked due to multiple failed login attempts',
          message: `Your account has been locked for ${process.env.ACCOUNT_LOCKOUT_DURATION_MINUTES || 15} minutes`
        });
      }
      
      return res.status(401).json({
        error: 'Invalid username or password',
        attemptsRemaining: Math.max(0, parseInt(process.env.MAX_LOGIN_ATTEMPTS || 3) - failedAttempts)
      });
    }
    
    // Step 4: Success - log it
    await authService.logLoginAttempt(username, ipAddress, userAgent, true);
    await authService.updateLastLogin(user.id);
    
    // Generate tokens
    const accessToken = tokenService.generateAccessToken(user);
    const refreshToken = await tokenService.generateRefreshToken(user.id);
    
    // Get user with roles
    const userWithRoles = await authService.getUserWithRoles(user.id);
    
    console.log(`✅ User logged in: ${username}`);
    
    res.json({
      message: 'Login successful',
      accessToken,
      refreshToken,
      user: userWithRoles
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
};

/**
 * Refresh access token using refresh token
 * POST /api/auth/refresh
 */
exports.refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token required' });
    }
    
    // Verify refresh token
    const user = await tokenService.verifyRefreshToken(refreshToken);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }
    
    // Generate new access token
    const accessToken = tokenService.generateAccessToken(user);
    
    res.json({
      accessToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({ error: 'Token refresh failed' });
  }
};

/**
 * Logout - revoke refresh token
 * POST /api/auth/logout
 */
exports.logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (refreshToken) {
      await tokenService.revokeRefreshToken(refreshToken);
    }
    
    console.log(`✅ User logged out: ${req.user?.username || 'unknown'}`);
    
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
};

/**
 * Get current user info
 * GET /api/auth/me
 */
exports.getCurrentUser = async (req, res) => {
  try {
    const user = await authService.getUserWithRoles(req.user.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ user });
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({ error: 'Failed to get user info' });
  }
};
```

## Step 6: Create Authentication Middleware

### `api/src/middleware/auth.js`

```javascript
const tokenService = require('../services/tokenService');
const authService = require('../services/authService');

/**
 * Middleware to verify JWT token
 * Adds user object to req.user
 */
exports.authenticate = async (req, res, next) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'No token provided'
      });
    }
    
    const token = authHeader.substring(7); // Remove 'Bearer ' prefix
    
    // Verify token
    const decoded = tokenService.verifyAccessToken(token);
    
    // Get user from database
    const user = await authService.findUserById(decoded.id);
    
    if (!user) {
      return res.status(401).json({
        error: 'Authentication failed',
        message: 'User not found'
      });
    }
    
    // Attach user to request
    req.user = user;
    
    next();
  } catch (error) {
    if (error.message === 'Token expired') {
      return res.status(401).json({
        error: 'Token expired',
        message: 'Please refresh your token'
      });
    }
    
    return res.status(401).json({
      error: 'Authentication failed',
      message: error.message
    });
  }
};

/**
 * Optional authentication - doesn't fail if no token
 * Useful for endpoints that work differently for authenticated users
 */
exports.optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next();
    }
    
    const token = authHeader.substring(7);
    const decoded = tokenService.verifyAccessToken(token);
    const user = await authService.findUserById(decoded.id);
    
    if (user) {
      req.user = user;
    }
    
    next();
  } catch (error) {
    // Continue without authentication
    next();
  }
};
```

## Step 7: Create Authentication Routes

### `api/src/routes/auth.js`

```javascript
const express = require('express');
const authController = require('../controllers/authController');
const { authenticate } = require('../middleware/auth');
const { registerValidation, loginValidation, validate } = require('../utils/validators');

const router = express.Router();

// Public routes
router.post('/register', registerValidation, validate, authController.register);
router.post('/login', loginValidation, validate, authController.login);
router.post('/refresh', authController.refresh);

// Protected routes
router.post('/logout', authenticate, authController.logout);
router.get('/me', authenticate, authController.getCurrentUser);

module.exports = router;
```

### Update `api/src/routes/index.js`

```javascript
const express = require('express');
const healthController = require('../controllers/healthController');
const authRoutes = require('./auth');

const router = express.Router();

// Health check
router.get('/health', healthController.healthCheck);

// Authentication routes
router.use('/auth', authRoutes);

module.exports = router;
```

## Step 8: Test the Authentication System

### 1. Restart the API

```bash
docker-compose restart api
docker-compose logs -f api
```

### 2. Register a New User

```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice_customer",
    "email": "alice@example.com",
    "password": "SecurePass123!",
    "first_name": "Alice",
    "last_name": "Johnson",
    "phone": "+1-555-0101"
  }'
```

Expected response:
```json
{
  "message": "User registered successfully",
  "user": {
    "id": 1,
    "username": "alice_customer",
    "email": "alice@example.com"
  }
}
```

### 3. Login with Username and Password

```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice_customer",
    "password": "SecurePass123!"
  }'
```

Expected response:
```json
{
  "message": "Login successful",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "a1b2c3d4e5f6...",
  "user": {
    "id": 1,
    "username": "alice_customer",
    "email": "alice@example.com",
    "roles": ["customer"]
  }
}
```

**Save the accessToken for next requests!**

### 4. Get Current User Info (Protected Route)

```bash
# Replace YOUR_ACCESS_TOKEN with the token from login response
curl -X GET http://localhost:3000/api/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 5. Test Failed Login (3 Times)

```bash
# Attempt 1
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice_customer",
    "password": "WrongPassword"
  }'

# Attempt 2
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice_customer",
    "password": "WrongPassword"
  }'

# Attempt 3
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice_customer",
    "password": "WrongPassword"
  }'
```

After 3 failed attempts, you should see:
```json
{
  "error": "Account locked due to multiple failed login attempts",
  "message": "Your account has been locked for 15 minutes"
}
```

### 6. Check Login Attempts in Database

```bash
docker exec -it banking-mysql mysql -u root -p
# Password: rootpass123

USE banking_db;

SELECT * FROM login_attempts ORDER BY attempted_at DESC LIMIT 10;
SELECT * FROM account_lockouts;

EXIT;
```

### 7. Test Token Refresh

```bash
# Use the refreshToken from login response
curl -X POST http://localhost:3000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

### 8. Test Logout

```bash
curl -X POST http://localhost:3000/api/auth/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

## Understanding JWT

### JWT Structure

A JWT consists of three parts separated by dots:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhbGljZSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
│                                     │                                  │
│         Header (Algorithm)          │         Payload (Data)          │      Signature
```

### Decode JWT (Online Tool)

Visit: https://jwt.io/

Paste your token to see:

**Header:**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload:**
```json
{
  "id": 1,
  "username": "alice_customer",
  "email": "alice@example.com",
  "iat": 1642345678,
  "exp": 1642346578,
  "iss": "banking-api",
  "sub": "1"
}
```

**⚠️ Important:** 
- Payload is **NOT encrypted**, only encoded (Base64)
- Never put sensitive data (passwords, SSN) in JWT
- Signature ensures token hasn't been tampered with

## Security Best Practices Demonstrated

### 1. Password Security
- ✅ Passwords hashed with bcrypt (salt rounds: 10)
- ✅ Never store plain text passwords
- ✅ Password validation (min 8 chars, uppercase, lowercase, number)

### 2. Token Security
- ✅ Short-lived access tokens (15 minutes)
- ✅ Long-lived refresh tokens stored in database
- ✅ Token revocation on logout
- ✅ Separate tokens for access and refresh

### 3. Account Security
- ✅ Track all login attempts
- ✅ Lock account after 3 failed attempts
- ✅ Automatic unlock after 15 minutes
- ✅ Log IP address and user agent

### 4. Input Validation
- ✅ Validate all user inputs
- ✅ Sanitize email addresses
- ✅ Strong password requirements
- ✅ Clear error messages

## Troubleshooting

### "Invalid token" error
- Token might be expired (15 minutes)
- Use refresh token to get new access token
- Check JWT_SECRET in .env matches

### "Account locked" even after 15 minutes
- Check system time in Docker container
- Clear account_lockouts table for testing:
  ```sql
  DELETE FROM account_lockouts WHERE user_id = 1;
  ```

### Can't login after registration
- Verify password meets requirements
- Check if user was created: `SELECT * FROM users;`
- Verify password_hash is not null

## Testing Your Understanding

Before moving to Part 3, ensure you can:

1. ✅ Register a new user with valid data
2. ✅ Login and receive JWT tokens
3. ✅ Use access token to access protected routes
4. ✅ Trigger account lockout with failed attempts
5. ✅ Refresh access token using refresh token
6. ✅ Logout and revoke tokens
7. ✅ Explain JWT structure and purpose
8. ✅ Understand why we hash passwords

## Discussion Questions

1. **Why use JWT instead of sessions?**
   - How does JWT enable stateless authentication?
   - What are the trade-offs?

2. **Access Token vs Refresh Token**
   - Why have two different tokens?
   - What happens if access token is stolen?
   - What happens if refresh token is stolen?

3. **Account Lockout Strategy**
   - Is 3 attempts reasonable? Too strict? Too lenient?
   - Should lockout be permanent or temporary?
   - How could an attacker abuse this feature?

4. **Password Security**
   - Why can't we reverse bcrypt hashes?
   - What is a "salt" in password hashing?
   - Could we use MD5 or SHA256 instead?

## Next Steps

✅ You've completed Part 2!

You now have a working authentication system with:
- User registration
- Password hashing
- JWT-based authentication
- Token refresh mechanism
- Security monitoring and lockout

In **Part 3**, we'll add:
- Google OAuth 2.0 login
- Third-party authentication
- OAuth callback handling
- Account linking

Continue to: [Part 3: Google OAuth Login with JWT](./3_google_oauth_jwt.md)

## Additional Resources

- [JWT Introduction](https://jwt.io/introduction)
- [bcrypt Explained](https://auth0.com/blog/hashing-in-action-understanding-bcrypt/)
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Express Validator Docs](https://express-validator.github.io/docs/)
