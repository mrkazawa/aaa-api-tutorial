# Part 3: Google OAuth Login with JWT

## Learning Objectives

By the end of this part, you will:
- ✅ Understand OAuth 2.0 authentication flow
- ✅ Set up Google OAuth 2.0 credentials
- ✅ Implement Passport.js Google strategy
- ✅ Handle OAuth callbacks and errors
- ✅ Link OAuth accounts with local users
- ✅ Issue JWT tokens after OAuth success
- ✅ Create a simple login page for testing

## Overview

In Part 3, we'll add **Google OAuth 2.0** as an alternative authentication method. Users can now choose to login with their Google account instead of creating a username/password.

## OAuth 2.0 Flow

```
┌─────────┐                                      ┌─────────────┐
│         │  1. Click "Login with Google"        │             │
│         │────────────────────────────────────▶ │             │
│         │                                      │             │
│         │  2. Redirect to Google               │             │
│         │────────────────────────────────────▶ │   Google    │
│  User   │                                      │   OAuth     │
│         │  3. User approves in Google          │   Server    │
│         │◀────────────────────────────────────│             │
│         │                                      │             │
│         │  4. Redirect back with code          │             │
│         │────────────────────────────────────▶ │             │
└─────────┘                                      └──────┬──────┘
                                                        │
                                                        │
                    ┌──────────────────────────────────┘
                    │  5. Exchange code for tokens
                    ▼
            ┌──────────────┐
            │   Banking    │
            │   API        │  6. Create/find user
            │              │  7. Generate JWT
            │              │  8. Return to client
            └──────────────┘
```

## Step 1: Get Google OAuth Credentials

### Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)

2. Create a new project:
   - Click "Select a project" → "New Project"
   - Name: "Banking API AAA"
   - Click "Create"

3. Enable Google+ API:
   - Go to "APIs & Services" → "Library"
   - Search for "Google+ API"
   - Click "Enable"

4. Create OAuth 2.0 Credentials:
   - Go to "APIs & Services" → "Credentials"
   - Click "Create Credentials" → "OAuth client ID"
   - Configure consent screen if prompted:
     - User Type: External
     - App name: "Banking API"
     - Support email: your-email@example.com
     - Save and continue
   
5. Create OAuth Client ID:
   - Application type: "Web application"
   - Name: "Banking API OAuth"
   - Authorized redirect URIs:
     - `http://localhost:3000/api/auth/google/callback`
   - Click "Create"

6. Copy credentials:
   - Client ID: `1234567890-abcdefghijklmnop.apps.googleusercontent.com`
   - Client Secret: `GOCSPX-abc123def456`

### Update .env file

```env
# Google OAuth Configuration
GOOGLE_CLIENT_ID=your-actual-client-id-here
GOOGLE_CLIENT_SECRET=your-actual-client-secret-here
GOOGLE_CALLBACK_URL=http://localhost:3000/api/auth/google/callback
```

## Step 2: Install Passport.js Dependencies

### Create public directory for static files

```bash
mkdir -p api/public
```

Update `api/package.json`:

```json
{
  "dependencies": {
    "express": "^4.18.2",
    "mysql2": "^3.6.5",
    "dotenv": "^16.3.1",
    "cors": "^2.8.5",
    "helmet": "^7.1.0",
    "bcrypt": "^5.1.1",
    "jsonwebtoken": "^9.0.2",
    "express-validator": "^7.0.1",
    "cookie-parser": "^1.4.6",
    "passport": "^0.7.0",
    "passport-google-oauth20": "^2.0.0",
    "express-session": "^1.17.3"
  }
}
```

Rebuild container:

```bash
docker-compose down
docker-compose up --build -d
```

**Understanding Passport.js:**
Passport.js is authentication middleware for Node.js. While we're using JWT for stateless authentication, Passport still requires session support during the OAuth callback flow. The session is used temporarily to store OAuth state, then we immediately issue JWTs.

## Step 3: Configure Passport with Google Strategy

### `api/src/config/passport.js`

```javascript
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const authService = require('../services/authService');

// Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
    scope: ['profile', 'email']
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      console.log('Google OAuth profile received:', profile.id);
      
      // Extract user information from Google profile
      const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
      const firstName = profile.name && profile.name.givenName ? profile.name.givenName : null;
      const lastName = profile.name && profile.name.familyName ? profile.name.familyName : null;
      
      if (!email) {
        return done(new Error('Email not provided by Google'), null);
      }
      
      // Try to find existing user by OAuth provider ID
      let user = await authService.findUserByOAuthId('google', profile.id);
      
      if (user) {
        console.log('Existing OAuth user found:', user.username);
        return done(null, user);
      }
      
      // Try to find existing user by email (link accounts)
      user = await authService.findUserByEmail(email);
      
      if (user) {
        // Link Google account to existing user
        console.log('Linking Google account to existing user:', email);
        await authService.linkOAuthProvider(user.id, 'google', profile.id);
        user.auth_provider = 'google';
        user.oauth_provider_id = profile.id;
        return done(null, user);
      }
      
      // Create new user
      console.log('Creating new user from Google OAuth');
      const newUser = await authService.createOAuthUser({
        email,
        firstName,
        lastName,
        authProvider: 'google',
        oauthProviderId: profile.id
      });
      
      return done(null, newUser);
      
    } catch (error) {
      console.error('Google OAuth error:', error);
      return done(error, null);
    }
  }
));

// Serialize user (not used in JWT strategy, but required by Passport)
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user (not used in JWT strategy, but required by Passport)
passport.deserializeUser(async (id, done) => {
  try {
    const user = await authService.findUserById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

module.exports = passport;
```

## Step 4: Extend Authentication Service

Add these functions to `api/src/services/authService.js`:

```javascript
/**
 * Find user by email
 * @param {string} email - Email address
 * @returns {Promise<object|null>} - User object or null
 */
exports.findUserByEmail = async (email) => {
  const [rows] = await db.query(
    'SELECT * FROM users WHERE email = ? AND is_active = TRUE',
    [email]
  );
  
  return rows.length > 0 ? rows[0] : null;
};

/**
 * Find user by OAuth provider ID
 * @param {string} provider - OAuth provider ('google')
 * @param {string} providerId - Provider's user ID
 * @returns {Promise<object|null>} - User object or null
 */
exports.findUserByOAuthId = async (provider, providerId) => {
  const [rows] = await db.query(
    'SELECT * FROM users WHERE auth_provider = ? AND oauth_provider_id = ? AND is_active = TRUE',
    [provider, providerId]
  );
  
  return rows.length > 0 ? rows[0] : null;
};

/**
 * Create user from OAuth provider
 * @param {object} userData - OAuth user data
 * @returns {Promise<object>} - Created user
 */
exports.createOAuthUser = async (userData) => {
  const { email, firstName, lastName, authProvider, oauthProviderId } = userData;
  
  // Generate username from email
  const baseUsername = email.split('@')[0].replace(/[^a-zA-Z0-9]/g, '_');
  let username = baseUsername;
  let counter = 1;
  
  // Ensure username is unique
  while (true) {
    const [existing] = await db.query('SELECT id FROM users WHERE username = ?', [username]);
    if (existing.length === 0) break;
    username = `${baseUsername}${counter}`;
    counter++;
  }
  
  // Insert user (no password_hash for OAuth users)
  const [result] = await db.query(
    `INSERT INTO users (username, email, first_name, last_name, auth_provider, oauth_provider_id, is_email_verified) 
     VALUES (?, ?, ?, ?, ?, ?, TRUE)`,
    [username, email, firstName || null, lastName || null, authProvider, oauthProviderId]
  );
  
  // Assign default 'customer' role
  const [roleResult] = await db.query('SELECT id FROM roles WHERE name = ?', ['customer']);
  if (roleResult.length > 0) {
    await db.query(
      'INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)',
      [result.insertId, roleResult[0].id]
    );
  }
  
  // Return created user
  const [newUser] = await db.query(
    'SELECT id, username, email, first_name, last_name, auth_provider, created_at FROM users WHERE id = ?',
    [result.insertId]
  );
  
  return newUser[0];
};

/**
 * Link OAuth provider to existing user
 * @param {number} userId - User ID
 * @param {string} provider - OAuth provider
 * @param {string} providerId - Provider's user ID
 */
exports.linkOAuthProvider = async (userId, provider, providerId) => {
  await db.query(
    'UPDATE users SET auth_provider = ?, oauth_provider_id = ?, is_email_verified = TRUE WHERE id = ?',
    [provider, providerId, userId]
  );
};
```

## Step 5: Update Authentication Controller

Add OAuth controller functions to `api/src/controllers/authController.js`:

```javascript
/**
 * Initiate Google OAuth flow
 * GET /api/auth/google
 */
exports.googleAuth = (req, res, next) => {
  const passport = require('../config/passport');
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false
  })(req, res, next);
};

/**
 * Google OAuth callback
 * GET /api/auth/google/callback
 */
exports.googleCallback = async (req, res, next) => {
  const passport = require('../config/passport');
  
  passport.authenticate('google', { session: false }, async (err, user, info) => {
    try {
      if (err) {
        console.error('OAuth error:', err.message);
        return res.redirect(`http://localhost:3000/login.html?error=${encodeURIComponent(err.message)}`);
      }
      
      if (!user) {
        console.error('OAuth failed: No user returned');
        return res.redirect('http://localhost:3000/login.html?error=authentication_failed');
      }
      
      // Log successful OAuth login
      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('user-agent') || 'unknown';
      await authService.logLoginAttempt(user.username, ipAddress, userAgent, true);
      await authService.updateLastLogin(user.id);
      
      // Generate JWT tokens
      const accessToken = tokenService.generateAccessToken(user);
      const refreshToken = await tokenService.generateRefreshToken(user.id);
      
      // Get user with roles
      const userWithRoles = await authService.getUserWithRoles(user.id);
      
      console.log(`✅ User logged in via Google OAuth: ${user.username}`);
      
      // Redirect to frontend with tokens
      // In production, use a more secure method (e.g., redirect to app with short-lived code)
      const redirectUrl = `http://localhost:3000/login.html?` +
        `success=true&` +
        `accessToken=${encodeURIComponent(accessToken)}&` +
        `refreshToken=${encodeURIComponent(refreshToken)}&` +
        `username=${encodeURIComponent(user.username)}`;
      
      res.redirect(redirectUrl);
      
    } catch (error) {
      console.error('OAuth callback error:', error);
      res.redirect('http://localhost:3000/login.html?error=server_error');
    }
  })(req, res, next);
};
```

## Step 6: Update Routes

Update `api/src/routes/auth.js`:

```javascript
const express = require('express');
const authController = require('../controllers/authController');
const { authenticate } = require('../middleware/auth');
const { registerValidation, loginValidation, validate } = require('../utils/validators');

const router = express.Router();

// Public routes - Local auth
router.post('/register', registerValidation, validate, authController.register);
router.post('/login', loginValidation, validate, authController.login);
router.post('/refresh', authController.refresh);

// Public routes - Google OAuth
router.get('/google', authController.googleAuth);
router.get('/google/callback', authController.googleCallback);

// Protected routes
router.post('/logout', authenticate, authController.logout);
router.get('/me', authenticate, authController.getCurrentUser);

module.exports = router;
```

## Step 7: Update App.js to Initialize Passport

Update `api/src/app.js`:

```javascript
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const passport = require('./config/passport');
const routes = require('./routes');

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false // Disable for development
}));

// CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  credentials: true
}));

// Body parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Initialize Passport
app.use(passport.initialize());

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Serve static files
app.use(express.static('public'));

// API routes
app.use('/api', routes);

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: '🏦 Welcome to Banking API',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      api: '/api',
      login: '/login.html'
    }
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.path
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

module.exports = app;
```

## Step 8: Create Simple Login Page

### `api/public/login.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Banking API - Login</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 10px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 400px;
            width: 100%;
        }
        
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        
        .alert {
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        
        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .alert-error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: 500;
        }
        
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .btn {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
            margin-bottom: 15px;
        }
        
        .btn-primary:hover {
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        .divider {
            text-align: center;
            margin: 20px 0;
            color: #999;
            position: relative;
        }
        
        .divider::before,
        .divider::after {
            content: '';
            position: absolute;
            top: 50%;
            width: 40%;
            height: 1px;
            background: #ddd;
        }
        
        .divider::before {
            left: 0;
        }
        
        .divider::after {
            right: 0;
        }
        
        .btn-google {
            background: white;
            color: #444;
            border: 2px solid #ddd;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        
        .btn-google:hover {
            background: #f8f9fa;
            border-color: #667eea;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .google-icon {
            width: 20px;
            height: 20px;
        }
        
        .token-display {
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            border: 1px solid #dee2e6;
        }
        
        .token-display h3 {
            font-size: 14px;
            margin-bottom: 10px;
            color: #333;
        }
        
        .token-box {
            background: white;
            padding: 10px;
            border-radius: 3px;
            word-break: break-all;
            font-family: monospace;
            font-size: 11px;
            color: #666;
            max-height: 100px;
            overflow-y: auto;
            margin-bottom: 10px;
        }
        
        .copy-btn {
            padding: 6px 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
        }
        
        .register-link {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 14px;
        }
        
        .register-link a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🏦 Banking API</h1>
        <p class="subtitle">AAA Security Educational Project</p>
        
        <div id="alertBox"></div>
        
        <form id="loginForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Enter your username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
        
        <div class="divider">OR</div>
        
        <button onclick="loginWithGoogle()" class="btn btn-google">
            <svg class="google-icon" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
            </svg>
            Continue with Google
        </button>
        
        <div id="tokenDisplay" style="display: none;" class="token-display">
            <h3>✅ Login Successful!</h3>
            <p><strong>Username:</strong> <span id="displayUsername"></span></p>
            <p><strong>Access Token:</strong></p>
            <div class="token-box" id="accessTokenBox"></div>
            <button class="copy-btn" onclick="copyToken('access')">Copy Access Token</button>
            
            <p style="margin-top: 15px;"><strong>Refresh Token:</strong></p>
            <div class="token-box" id="refreshTokenBox"></div>
            <button class="copy-btn" onclick="copyToken('refresh')">Copy Refresh Token</button>
        </div>
        
        <div class="register-link">
            Don't have an account? <a href="#" onclick="showRegisterInfo()">Register</a>
        </div>
    </div>
    
    <script>
        let accessToken = '';
        let refreshToken = '';
        
        // Check URL parameters for OAuth callback
        window.addEventListener('DOMContentLoaded', () => {
            const params = new URLSearchParams(window.location.search);
            
            if (params.get('success') === 'true') {
                accessToken = params.get('accessToken');
                refreshToken = params.get('refreshToken');
                const username = params.get('username');
                
                showAlert('Login successful! Welcome, ' + username, 'success');
                displayTokens(username, accessToken, refreshToken);
                
                // Clean URL
                window.history.replaceState({}, document.title, window.location.pathname);
            } else if (params.get('error')) {
                const error = params.get('error');
                showAlert('Login failed: ' + error.replace(/_/g, ' '), 'error');
            }
        });
        
        // Handle form submission
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch('http://localhost:3000/api/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    accessToken = data.accessToken;
                    refreshToken = data.refreshToken;
                    showAlert('Login successful! Welcome, ' + data.user.username, 'success');
                    displayTokens(data.user.username, accessToken, refreshToken);
                } else {
                    showAlert(data.error || 'Login failed', 'error');
                }
            } catch (error) {
                showAlert('Network error: ' + error.message, 'error');
            }
        });
        
        function loginWithGoogle() {
            window.location.href = 'http://localhost:3000/api/auth/google';
        }
        
        function showAlert(message, type) {
            const alertBox = document.getElementById('alertBox');
            alertBox.innerHTML = `<div class="alert alert-${type}">${message}</div>`;
            
            // Auto-hide after 5 seconds
            setTimeout(() => {
                alertBox.innerHTML = '';
            }, 5000);
        }
        
        function displayTokens(username, access, refresh) {
            document.getElementById('displayUsername').textContent = username;
            document.getElementById('accessTokenBox').textContent = access;
            document.getElementById('refreshTokenBox').textContent = refresh;
            document.getElementById('tokenDisplay').style.display = 'block';
        }
        
        function copyToken(type) {
            const token = type === 'access' ? accessToken : refreshToken;
            navigator.clipboard.writeText(token).then(() => {
                showAlert(`${type === 'access' ? 'Access' : 'Refresh'} token copied to clipboard!`, 'success');
            });
        }
        
        function showRegisterInfo() {
            alert('To register, use the API endpoint:\n\n' +
                  'POST http://localhost:3000/api/auth/register\n\n' +
                  'Body:\n' +
                  '{\n' +
                  '  "username": "your_username",\n' +
                  '  "email": "your@email.com",\n' +
                  '  "password": "SecurePass123!",\n' +
                  '  "first_name": "Your Name"\n' +
                  '}');
        }
    </script>
</body>
</html>
```

## Step 9: Test Google OAuth

### 1. Restart API

```bash
docker-compose restart api
docker-compose logs -f api
```

### 2. Open Login Page

Open browser: `http://localhost:3000/login.html`

### 3. Test Regular Login

- Enter username and password
- Click "Login"
- See tokens displayed on page

### 4. Test Google OAuth

- Click "Continue with Google"
- Select your Google account
- Grant permissions
- Redirected back with tokens

### 5. Verify in Database

```bash
docker exec -it banking-mysql mysql -u root -p
# Password: rootpass123

USE banking_db;

-- Check users created via OAuth
SELECT id, username, email, auth_provider, oauth_provider_id, created_at 
FROM users 
WHERE auth_provider = 'google';

-- Check login attempts
SELECT * FROM login_attempts ORDER BY attempted_at DESC LIMIT 5;

EXIT;
```

## Understanding OAuth 2.0

### Key Concepts

1. **Authorization Server** - Google's OAuth server
2. **Resource Owner** - The user
3. **Client** - Our Banking API
4. **Redirect URI** - Where Google sends user after authentication
5. **Scopes** - What data we request (profile, email)

### Security Benefits

- ✅ User doesn't share password with our app
- ✅ Google handles authentication
- ✅ Can revoke access anytime from Google account
- ✅ Two-factor authentication from Google
- ✅ Email verified automatically

### Flow Details

1. **User clicks "Login with Google"**
   - App redirects to: `https://accounts.google.com/o/oauth2/v2/auth?client_id=...`

2. **User approves in Google**
   - Google redirects to: `http://localhost:3000/api/auth/google/callback?code=...`

3. **App exchanges code for tokens**
   - Passport.js handles this automatically
   - Gets access token and user profile

4. **App creates/finds user**
   - If new user, create account
   - If existing email, link accounts
   - If existing OAuth user, login

5. **App issues JWT**
   - Generate access token and refresh token
   - Same tokens as username/password login

## Account Linking

### Scenario 1: New OAuth User
```
User logs in with Google → New account created → Assigned customer role
```

### Scenario 2: Existing Email
```
User registered with email@example.com and password
User logs in with Google using same email@example.com
→ Accounts linked automatically
→ Can login with either method
```

### Scenario 3: Existing OAuth User
```
User previously logged in with Google
User logs in with Google again
→ Found by oauth_provider_id
→ Login successful
```

## Testing Your Understanding

Before moving to Part 4, ensure you can:

1. ✅ Create Google OAuth credentials
2. ✅ Configure environment variables
3. ✅ Login with Google account
4. ✅ Receive JWT tokens after OAuth
5. ✅ Understand OAuth 2.0 flow
6. ✅ Explain difference between OAuth and username/password
7. ✅ Understand account linking

## Troubleshooting

### "redirect_uri_mismatch" error
- Verify redirect URI in Google Console matches exactly:
  - `http://localhost:3000/api/auth/google/callback`
- No trailing slash
- Must use http:// for localhost

### "Email not provided by Google"
- In Google Console, ensure email scope is requested
- Check OAuth consent screen includes email

### User created with weird username
- OAuth users get username from email (before @)
- Special characters replaced with underscore
- Number appended if username exists

### Can't link accounts
- Accounts linked by email automatically
- Email must match exactly
- Check `auth_provider` and `oauth_provider_id` columns

## Discussion Questions

1. **OAuth vs Password Authentication**
   - Which is more secure? Why?
   - What are the trade-offs?
   - When should you use each?

2. **Account Linking**
   - Is it safe to automatically link accounts by email?
   - What if someone else owns that email?
   - How could this be improved?

3. **Token Scope**
   - Why do we only request 'profile' and 'email'?
   - What other scopes could we request?
   - Privacy implications?

4. **Security Considerations**
   - What if Google's OAuth is compromised?
   - Should we allow OAuth-only accounts?
   - How to handle OAuth provider errors?

## Next Steps

✅ You've completed Part 3!

Users can now authenticate with:
- Username and password
- Google OAuth 2.0

Both methods issue JWT tokens for authorization.

In **Part 4**, we'll implement:
- Role-Based Access Control (RBAC)
- Protect endpoints by role
- Admin, Manager, Customer roles
- Permission checking

Continue to: [Part 4: RBAC Authorization](./4_rbac_authorization.md)

## Additional Resources

- [OAuth 2.0 Simplified](https://aaronparecki.com/oauth-2-simplified/)
- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [Passport.js Documentation](http://www.passportjs.org/docs/)
- [OWASP OAuth Security](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
