# Part 1: Docker Compose Setup

## Learning Objectives

By the end of this part, you will:
- ✅ Understand Docker Compose for multi-container applications
- ✅ Set up Express.js API with MySQL database
- ✅ Design database schema for a banking application
- ✅ Create basic API endpoints and health checks
- ✅ Test database connectivity

## Overview

In this first part, we'll set up the foundation of our banking API using Docker Compose. We'll create three services:
1. **Express.js API** - Our backend application
2. **MySQL 8.0** - Database to store users, accounts, and transactions
3. **phpMyAdmin** - Web interface to view and manage the database

## Architecture Diagram

```
┌─────────────────────────────────────────────────┐
│                Docker Network                    │
│                                                  │
│  ┌────────────┐    ┌──────────┐    ┌──────────┐│
│  │  Express   │───▶│  MySQL   │◀───│phpMyAdmin││
│  │    API     │    │ Database │    │   Web    ││
│  │  :3000     │    │  :3306   │    │  :8080   ││
│  └────────────┘    └──────────┘    └──────────┘│
│                                                  │
└─────────────────────────────────────────────────┘
```

## Step 1: Create Project Structure

Create the following directory structure:

```bash
api-app/
├── docker-compose.yml
├── .env.example
├── .gitignore
├── README.md
└── api/
    ├── Dockerfile
    ├── package.json
    ├── .dockerignore
    ├── public/              # Static files (added in Part 3)
    └── src/
        ├── server.js
        ├── app.js
        ├── config/
        │   └── database.js
        ├── routes/
        │   └── index.js
        ├── controllers/
        │   └── healthController.js
        ├── models/          # Database models (added in Part 4)
        ├── middleware/      # Auth/RBAC/ABAC (added in Parts 2-5)
        ├── services/        # Business logic (added in Part 2)
        ├── utils/           # Helper functions (added in Part 2)
        └── db/
            └── migrations/
                └── init.sql
```

## Step 2: Create Environment Configuration

### `.env.example`

Create this file in the root directory:

**Note:** This file includes all environment variables for Parts 1-6. You'll add the actual values as you progress through the tutorial.

```env
# Node Environment
NODE_ENV=development
PORT=3000

# MySQL Database Configuration
DB_HOST=mysql
DB_PORT=3306
DB_USER=bankuser
DB_PASSWORD=bankpass123
DB_NAME=banking_db
MYSQL_ROOT_PASSWORD=rootpass123

# JWT Configuration (we'll use this later)
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRATION=15m
REFRESH_TOKEN_EXPIRATION=7d

# Google OAuth (we'll use this in Part 3)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_CALLBACK_URL=http://localhost:3000/api/auth/google/callback

# Security Settings
BCRYPT_ROUNDS=10
MAX_LOGIN_ATTEMPTS=3
ACCOUNT_LOCKOUT_DURATION_MINUTES=15

# CORS
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
```

### `.gitignore`

```
# Dependencies
node_modules/
package-lock.json

# Environment variables
.env

# Logs
logs/
*.log

# Docker
docker-compose.override.yml

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Database
*.sql~
```

## Step 3: Docker Compose Configuration

### `docker-compose.yml`

```yaml
version: '3.8'

services:
  # Express.js API
  api:
    build:
      context: ./api
      dockerfile: Dockerfile
    container_name: banking-api
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=${NODE_ENV:-development}
      - PORT=${PORT:-3000}
      - DB_HOST=mysql
      - DB_PORT=3306
      - DB_USER=${DB_USER}
      - DB_PASSWORD=${DB_PASSWORD}
      - DB_NAME=${DB_NAME}
      - JWT_SECRET=${JWT_SECRET}
      - JWT_EXPIRATION=${JWT_EXPIRATION}
      - REFRESH_TOKEN_EXPIRATION=${REFRESH_TOKEN_EXPIRATION}
    volumes:
      - ./api/src:/app/src
      - /app/node_modules
    depends_on:
      mysql:
        condition: service_healthy
    networks:
      - banking-network
    restart: unless-stopped
    command: npm run dev

  # MySQL Database
  mysql:
    image: mysql:8.0
    container_name: banking-mysql
    environment:
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD}
      MYSQL_DATABASE: ${DB_NAME}
      MYSQL_USER: ${DB_USER}
      MYSQL_PASSWORD: ${DB_PASSWORD}
    ports:
      - "3306:3306"
    volumes:
      - mysql-data:/var/lib/mysql
      - ./api/src/db/migrations/init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - banking-network
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost", "-u", "root", "-p${MYSQL_ROOT_PASSWORD}"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  # phpMyAdmin
  phpmyadmin:
    image: phpmyadmin:latest
    container_name: banking-phpmyadmin
    environment:
      PMA_HOST: mysql
      PMA_PORT: 3306
      PMA_USER: root
      PMA_PASSWORD: ${MYSQL_ROOT_PASSWORD}
      UPLOAD_LIMIT: 100M
    ports:
      - "8080:80"
    depends_on:
      - mysql
    networks:
      - banking-network
    restart: unless-stopped

volumes:
  mysql-data:
    driver: local

networks:
  banking-network:
    driver: bridge
```

## Step 4: Create Express.js Application

### `api/Dockerfile`

```dockerfile
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy application source
COPY . .

# Expose port
EXPOSE 3000

# Start application
CMD ["npm", "run", "dev"]
```

### `api/.dockerignore`

```
node_modules
npm-debug.log
.env
.git
.gitignore
README.md
```

### `api/package.json`

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
    "helmet": "^7.1.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.2"
  }
}
```

### `api/src/server.js`

```javascript
require('dotenv').config();
const app = require('./app');
const db = require('./config/database');

const PORT = process.env.PORT || 3000;

// Test database connection
db.getConnection()
  .then(connection => {
    console.log('✅ Database connected successfully');
    connection.release();
    
    // Start server
    app.listen(PORT, () => {
      console.log(`🚀 Banking API server running on port ${PORT}`);
      console.log(`📊 Environment: ${process.env.NODE_ENV}`);
      console.log(`🔗 API: http://localhost:${PORT}`);
      console.log(`🗄️  Database: ${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`);
    });
  })
  .catch(err => {
    console.error('❌ Database connection failed:', err.message);
    process.exit(1);
  });

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  db.end();
  process.exit(0);
});
```

### `api/src/app.js`

```javascript
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const routes = require('./routes');

const app = express();

// Security middleware
app.use(helmet());

// CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  credentials: true
}));

// Body parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// API routes
app.use('/api', routes);

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: '🏦 Welcome to Banking API',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      api: '/api'
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

### `api/src/config/database.js`

```javascript
const mysql = require('mysql2');

// Create connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0
});

// Promisify for async/await
const promisePool = pool.promise();

module.exports = promisePool;
```

### `api/src/routes/index.js`

```javascript
const express = require('express');
const healthController = require('../controllers/healthController');

const router = express.Router();

// Health check endpoint
router.get('/health', healthController.healthCheck);

module.exports = router;
```

### `api/src/controllers/healthController.js`

```javascript
const db = require('../config/database');

exports.healthCheck = async (req, res) => {
  try {
    // Check database connection
    await db.query('SELECT 1');
    
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      database: 'connected',
      environment: process.env.NODE_ENV
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      database: 'disconnected',
      error: error.message
    });
  }
};
```

## Step 5: Database Schema for Banking System

### `api/src/db/migrations/init.sql`

```sql
-- Banking API Database Schema
-- Part 1: Initial Setup

-- Enable foreign key checks
SET FOREIGN_KEY_CHECKS = 1;

-- ===================================
-- USERS AND AUTHENTICATION
-- ===================================

-- Users table (will be expanded in Part 2)
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) COMMENT 'NULL for OAuth-only users',
    auth_provider ENUM('local', 'google') DEFAULT 'local',
    oauth_provider_id VARCHAR(255) COMMENT 'Google user ID',
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    phone VARCHAR(20),
    is_active BOOLEAN DEFAULT TRUE,
    is_email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP NULL,
    INDEX idx_email (email),
    INDEX idx_username (username),
    INDEX idx_oauth (auth_provider, oauth_provider_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===================================
-- ROLES AND PERMISSIONS (RBAC)
-- ===================================

-- Roles table (will be used in Part 4)
CREATE TABLE IF NOT EXISTS roles (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50) UNIQUE NOT NULL COMMENT 'admin, manager, customer',
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) UNIQUE NOT NULL COMMENT 'account:read, transaction:create, etc',
    resource VARCHAR(50) NOT NULL COMMENT 'account, transaction, user',
    action VARCHAR(50) NOT NULL COMMENT 'create, read, update, delete',
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_resource_action (resource, action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- User-Role mapping (many-to-many)
CREATE TABLE IF NOT EXISTS user_roles (
    user_id INT NOT NULL,
    role_id INT NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_by INT COMMENT 'Admin user who assigned this role',
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Role-Permission mapping (many-to-many)
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INT NOT NULL,
    permission_id INT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===================================
-- USER ATTRIBUTES (ABAC)
-- ===================================

-- User attributes for ABAC (will be used in Part 5)
CREATE TABLE IF NOT EXISTS user_attributes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    attribute_key VARCHAR(50) NOT NULL COMMENT 'branch_id, department, account_type, daily_limit',
    attribute_value VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_attribute (user_id, attribute_key),
    INDEX idx_attribute_key (attribute_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===================================
-- BANKING ENTITIES
-- ===================================

-- Bank branches
CREATE TABLE IF NOT EXISTS branches (
    id INT PRIMARY KEY AUTO_INCREMENT,
    branch_code VARCHAR(10) UNIQUE NOT NULL,
    branch_name VARCHAR(100) NOT NULL,
    address TEXT,
    city VARCHAR(50),
    state VARCHAR(50),
    phone VARCHAR(20),
    manager_id INT COMMENT 'User ID of branch manager',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (manager_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_branch_code (branch_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Bank accounts
CREATE TABLE IF NOT EXISTS accounts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    account_number VARCHAR(20) UNIQUE NOT NULL,
    user_id INT NOT NULL,
    branch_id INT NOT NULL,
    account_type ENUM('savings', 'checking', 'business') NOT NULL DEFAULT 'savings',
    balance DECIMAL(15, 2) NOT NULL DEFAULT 0.00,
    currency VARCHAR(3) DEFAULT 'USD',
    status ENUM('active', 'frozen', 'closed') DEFAULT 'active',
    overdraft_limit DECIMAL(15, 2) DEFAULT 0.00,
    interest_rate DECIMAL(5, 4) DEFAULT 0.0000 COMMENT 'Annual interest rate',
    opened_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (branch_id) REFERENCES branches(id),
    INDEX idx_user_id (user_id),
    INDEX idx_account_number (account_number),
    INDEX idx_status (status),
    CHECK (balance >= -overdraft_limit)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Transactions
CREATE TABLE IF NOT EXISTS transactions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    transaction_type ENUM('deposit', 'withdrawal', 'transfer', 'fee', 'interest') NOT NULL,
    from_account_id INT COMMENT 'Source account for transfers/withdrawals',
    to_account_id INT COMMENT 'Destination account for transfers/deposits',
    amount DECIMAL(15, 2) NOT NULL,
    currency VARCHAR(3) DEFAULT 'USD',
    description TEXT,
    reference_number VARCHAR(50) UNIQUE NOT NULL,
    status ENUM('pending', 'completed', 'failed', 'reversed') DEFAULT 'pending',
    initiated_by INT NOT NULL COMMENT 'User who initiated the transaction',
    balance_before DECIMAL(15, 2),
    balance_after DECIMAL(15, 2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    FOREIGN KEY (from_account_id) REFERENCES accounts(id),
    FOREIGN KEY (to_account_id) REFERENCES accounts(id),
    FOREIGN KEY (initiated_by) REFERENCES users(id),
    INDEX idx_from_account (from_account_id),
    INDEX idx_to_account (to_account_id),
    INDEX idx_reference (reference_number),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at),
    CHECK (amount > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===================================
-- SECURITY AND AUDIT
-- ===================================

-- Login attempts tracking (will be used in Part 2 & 6)
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45) NOT NULL COMMENT 'Supports IPv6',
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(100) COMMENT 'invalid_password, user_not_found, account_locked',
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username_time (username, attempted_at),
    INDEX idx_ip_time (ip_address, attempted_at),
    INDEX idx_success (success)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Account lockouts (will be used in Part 2 & 6)
CREATE TABLE IF NOT EXISTS account_lockouts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    locked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    unlock_at TIMESTAMP NOT NULL,
    reason VARCHAR(255) DEFAULT 'Multiple failed login attempts',
    locked_by_system BOOLEAN DEFAULT TRUE,
    is_unlocked BOOLEAN DEFAULT FALSE,
    unlocked_at TIMESTAMP NULL,
    unlocked_by INT COMMENT 'Admin who manually unlocked',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (unlocked_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_unlock (user_id, unlock_at),
    INDEX idx_is_unlocked (is_unlocked)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Audit logs (will be used in Part 6)
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    action VARCHAR(100) NOT NULL COMMENT 'login, logout, account_created, transaction_completed',
    resource_type VARCHAR(50) COMMENT 'account, transaction, user',
    resource_id INT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    request_method VARCHAR(10) COMMENT 'GET, POST, PUT, DELETE',
    request_path VARCHAR(255),
    status_code INT,
    details JSON COMMENT 'Additional context',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_action_time (user_id, action, created_at),
    INDEX idx_resource (resource_type, resource_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Refresh tokens for JWT (will be used in Part 2)
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token (token),
    INDEX idx_user_expires (user_id, expires_at),
    INDEX idx_revoked (revoked)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===================================
-- SEED DATA
-- ===================================

-- Insert default roles
INSERT INTO roles (name, description) VALUES
('admin', 'System administrator with full access'),
('manager', 'Branch manager with access to branch accounts'),
('customer', 'Regular customer with access to own accounts')
ON DUPLICATE KEY UPDATE description = VALUES(description);

-- Insert permissions
INSERT INTO permissions (name, resource, action, description) VALUES
-- Account permissions
('account:create', 'account', 'create', 'Create new bank accounts'),
('account:read', 'account', 'read', 'View own accounts'),
('account:read:all', 'account', 'read', 'View all accounts (admin)'),
('account:read:branch', 'account', 'read', 'View branch accounts (manager)'),
('account:update', 'account', 'update', 'Update account settings'),
('account:close', 'account', 'delete', 'Close account'),

-- Transaction permissions
('transaction:create', 'transaction', 'create', 'Create transactions (deposit/withdrawal/transfer)'),
('transaction:read', 'transaction', 'read', 'View own transactions'),
('transaction:read:all', 'transaction', 'read', 'View all transactions (admin)'),
('transaction:read:branch', 'transaction', 'read', 'View branch transactions (manager)'),
('transaction:reverse', 'transaction', 'update', 'Reverse transactions'),

-- User management permissions
('user:create', 'user', 'create', 'Create users'),
('user:read', 'user', 'read', 'View users'),
('user:update', 'user', 'update', 'Update users'),
('user:delete', 'user', 'delete', 'Delete users'),
('user:manage:roles', 'user', 'update', 'Assign roles to users'),

-- Branch permissions
('branch:read', 'branch', 'read', 'View branch information'),
('branch:manage', 'branch', 'update', 'Manage branch settings'),

-- Audit permissions
('audit:read', 'audit', 'read', 'View audit logs'),
('security:manage', 'security', 'update', 'Manage security settings (unlock accounts)')
ON DUPLICATE KEY UPDATE description = VALUES(description);

-- Assign permissions to roles

-- Admin gets all permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id 
FROM roles r, permissions p 
WHERE r.name = 'admin'
ON DUPLICATE KEY UPDATE role_id = VALUES(role_id);

-- Manager permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id 
FROM roles r, permissions p 
WHERE r.name = 'manager' 
AND p.name IN (
    'account:read:branch',
    'transaction:read:branch',
    'transaction:create',
    'branch:read',
    'user:read'
)
ON DUPLICATE KEY UPDATE role_id = VALUES(role_id);

-- Customer permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id 
FROM roles r, permissions p 
WHERE r.name = 'customer' 
AND p.name IN (
    'account:create',
    'account:read',
    'account:update',
    'account:close',
    'transaction:create',
    'transaction:read'
)
ON DUPLICATE KEY UPDATE role_id = VALUES(role_id);

-- Create sample branch
INSERT INTO branches (branch_code, branch_name, address, city, state, phone) VALUES
('MAIN001', 'Main Street Branch', '123 Main Street', 'New York', 'NY', '+1-555-0100'),
('WEST002', 'West Side Branch', '456 West Avenue', 'Los Angeles', 'CA', '+1-555-0200')
ON DUPLICATE KEY UPDATE branch_name = VALUES(branch_name);

-- ===================================
-- VIEWS FOR EASIER QUERIES
-- ===================================

-- View: User with roles
CREATE OR REPLACE VIEW user_roles_view AS
SELECT 
    u.id AS user_id,
    u.username,
    u.email,
    GROUP_CONCAT(r.name) AS roles
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
GROUP BY u.id;

-- View: Active accounts summary
CREATE OR REPLACE VIEW active_accounts_view AS
SELECT 
    a.id,
    a.account_number,
    a.account_type,
    a.balance,
    a.status,
    u.username,
    u.email,
    b.branch_name
FROM accounts a
JOIN users u ON a.user_id = u.id
JOIN branches b ON a.branch_id = b.id
WHERE a.status = 'active';

-- Success message
SELECT '✅ Database schema created successfully!' AS message;
```

## Step 6: Setup and Test

### Create .env file

```bash
# Copy the example file
cp .env.example .env

# Edit with your values (you can use the defaults for now)
nano .env
```

### Build and start services

```bash
# Build and start all containers
docker-compose up -d

# View logs
docker-compose logs -f

# Check running containers
docker-compose ps
```

Expected output:
```
NAME                  STATUS              PORTS
banking-api           Up 30 seconds       0.0.0.0:3000->3000/tcp
banking-mysql         Up 30 seconds       0.0.0.0:3306->3306/tcp
banking-phpmyadmin    Up 30 seconds       0.0.0.0:8080->80/tcp
```

### Test the API

#### 1. Health Check
```bash
curl http://localhost:3000/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "uptime": 15.234,
  "database": "connected",
  "environment": "development"
}
```

#### 2. Root Endpoint
```bash
curl http://localhost:3000/
```

#### 3. Check phpMyAdmin
Open browser: `http://localhost:8080`
- Username: `root`
- Password: `rootpass123` (from .env)

Verify tables exist:
- users
- roles
- permissions
- accounts
- transactions
- login_attempts
- audit_logs

## Step 7: Verify Database

### Connect to MySQL container
```bash
docker exec -it banking-mysql mysql -u root -p
# Enter password: rootpass123
```

### Run queries
```sql
-- Check database
SHOW DATABASES;
USE banking_db;

-- Check tables
SHOW TABLES;

-- Check roles
SELECT * FROM roles;

-- Check permissions
SELECT * FROM permissions;

-- Check role-permission mappings
SELECT 
    r.name AS role,
    p.name AS permission
FROM role_permissions rp
JOIN roles r ON rp.role_id = r.id
JOIN permissions p ON rp.permission_id = p.id
ORDER BY r.name, p.name;

-- Check branches
SELECT * FROM branches;

-- Exit
EXIT;
```

## Understanding What We Built

### Docker Compose Services

1. **API Service**
   - Built from `api/Dockerfile`
   - Exposes port 3000
   - Mounts source code for hot reload
   - Waits for MySQL to be healthy before starting

2. **MySQL Service**
   - Uses official MySQL 8.0 image
   - Initializes database from `init.sql`
   - Persists data in Docker volume
   - Health check ensures it's ready

3. **phpMyAdmin Service**
   - Web UI for database management
   - Connects to MySQL automatically
   - Useful for debugging and viewing data

### Database Schema

#### Core Tables (Part 1)
- `users` - User accounts
- `roles` - Admin, Manager, Customer
- `permissions` - Granular access rights
- `branches` - Bank branches
- `accounts` - Bank accounts
- `transactions` - Money movements

#### Security Tables (will be used in later parts)
- `login_attempts` - Track authentication attempts
- `account_lockouts` - Security lockouts
- `audit_logs` - Comprehensive activity logging
- `refresh_tokens` - JWT token management
- `user_attributes` - ABAC attributes

### RBAC Setup

We've defined three roles with different permissions:

**Admin**
- Full system access
- All permissions

**Manager**
- View branch accounts and transactions
- Manage branch operations
- Limited user management

**Customer**
- Manage own accounts
- Create transactions
- View own transaction history

## Troubleshooting

### Port already in use
```bash
# Check what's using the port
sudo lsof -i :3000

# Change port in .env
PORT=3001
```

### MySQL connection refused
```bash
# Wait for MySQL to be fully ready
docker-compose logs mysql

# Restart services
docker-compose restart
```

### Permission denied errors
```bash
# Fix file permissions
sudo chown -R $USER:$USER .

# Rebuild containers
docker-compose down
docker-compose up --build
```

### Clear everything and start fresh
```bash
# Stop and remove containers, volumes, and networks
docker-compose down -v

# Remove built images
docker-compose down --rmi all

# Start fresh
docker-compose up --build
```

## Testing Your Understanding

Before moving to Part 2, ensure you can:

1. ✅ Start all services with `docker-compose up`
2. ✅ Access API at http://localhost:3000
3. ✅ Access phpMyAdmin at http://localhost:8080
4. ✅ Verify health check returns "healthy"
5. ✅ View all tables in phpMyAdmin
6. ✅ Understand the role-permission structure
7. ✅ Execute SQL queries in MySQL

## Discussion Questions

1. **Why use Docker Compose?**
   - What advantages does it provide over manual setup?
   - How does it help with "works on my machine" problems?

2. **Database Design**
   - Why separate roles and permissions into different tables?
   - What's the purpose of the many-to-many relationship?
   - How does this design support RBAC?

3. **Security Considerations**
   - Why store password_hash instead of password?
   - What's the purpose of the login_attempts table?
   - How does the account_lockouts table improve security?

## Next Steps

✅ You've completed Part 1! 

Your development environment is ready. In **Part 2**, we'll implement:
- User registration
- Password hashing with bcrypt
- Login with username/password
- JWT token generation
- Protected routes

Continue to: [Part 2: Username & Password Login with JWT](./2_username_password_jwt.md)

## Additional Resources

- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Express.js Guide](https://expressjs.com/en/guide/routing.html)
- [MySQL 8.0 Reference](https://dev.mysql.com/doc/refman/8.0/en/)
- [Database Design Best Practices](https://www.sqlshack.com/learn-sql-database-design/)
