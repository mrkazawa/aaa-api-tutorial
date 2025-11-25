# Part 4: Role-Based Access Control (RBAC)

## Learning Objectives

By the end of this part, you will:
- ✅ Understand Role-Based Access Control (RBAC) concepts
- ✅ Implement role checking middleware
- ✅ Implement permission-based authorization
- ✅ Create banking endpoints with role restrictions
- ✅ Test different access scenarios
- ✅ Understand role hierarchies

## Overview

In Part 4, we'll implement **Authorization** - the second "A" in AAA security. While authentication verifies *who you are*, authorization determines *what you can do*.

RBAC controls access based on roles assigned to users. We have three roles:
- **Customer** - Regular banking customers
- **Manager** - Branch managers
- **Admin** - System administrators

## RBAC Concepts

### What is RBAC?

Role-Based Access Control (RBAC) assigns permissions to roles, then assigns roles to users. This simplifies permission management.

```
User ──▶ Role ──▶ Permissions ──▶ Resources
```

**Example:**
```
Alice ──▶ Customer ──▶ [account:read, account:create] ──▶ Can create accounts
Bob   ──▶ Manager  ──▶ [account:read:branch, ...]      ──▶ Can view branch accounts
Carol ──▶ Admin    ──▶ [ALL PERMISSIONS]               ──▶ Can do everything
```

### Benefits of RBAC

1. **Simplified Management** - Assign roles instead of individual permissions
2. **Consistent Permissions** - All users with same role have same access
3. **Easy Auditing** - Track access by role
4. **Scalability** - Add new users without managing individual permissions

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Client Request                      │
│         Authorization: Bearer <JWT>              │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
    ┌────────────────────────┐
    │   authenticate()       │  Verify JWT
    │   Extract user         │
    └───────────┬────────────┘
                │
                ▼
    ┌────────────────────────┐
    │   requireRole()        │  Check if user has role
    │   OR                   │  - Customer?
    │   requirePermission()  │  - Manager?
    │                        │  - Admin?
    └───────────┬────────────┘
                │
        ┌───────┴───────┐
        │               │
    ALLOWED        FORBIDDEN
        │               │
        ▼               ▼
    Process         403 Error
    Request
```

## Step 1: Create RBAC Middleware

### `api/src/middleware/rbac.js`

```javascript
const db = require('../config/database');

/**
 * Get user's roles
 * @param {number} userId - User ID
 * @returns {Promise<Array>} - Array of role names
 */
async function getUserRoles(userId) {
  const [rows] = await db.query(
    `SELECT r.name 
     FROM roles r
     JOIN user_roles ur ON r.id = ur.role_id
     WHERE ur.user_id = ?`,
    [userId]
  );
  
  return rows.map(row => row.name);
}

/**
 * Get user's permissions
 * @param {number} userId - User ID
 * @returns {Promise<Array>} - Array of permission names
 */
async function getUserPermissions(userId) {
  const [rows] = await db.query(
    `SELECT DISTINCT p.name
     FROM permissions p
     JOIN role_permissions rp ON p.id = rp.permission_id
     JOIN user_roles ur ON rp.role_id = ur.role_id
     WHERE ur.user_id = ?`,
    [userId]
  );
  
  return rows.map(row => row.name);
}

/**
 * Middleware: Require specific role(s)
 * @param {Array|string} allowedRoles - Role name(s) required
 * @returns {Function} - Express middleware
 * 
 * @example
 * router.get('/admin/users', authenticate, requireRole('admin'), listUsers);
 * router.get('/branch', authenticate, requireRole(['manager', 'admin']), getBranchData);
 */
exports.requireRole = (allowedRoles) => {
  // Normalize to array
  const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];
  
  return async (req, res, next) => {
    try {
      // User should be attached by authenticate middleware
      if (!req.user) {
        return res.status(401).json({
          error: 'Authentication required',
          message: 'You must be logged in to access this resource'
        });
      }
      
      // Get user's roles
      const userRoles = await getUserRoles(req.user.id);
      
      // Check if user has any of the allowed roles
      const hasRole = userRoles.some(role => roles.includes(role));
      
      if (!hasRole) {
        console.log(`❌ Access denied: User ${req.user.username} (roles: ${userRoles.join(', ')}) tried to access ${req.path} (requires: ${roles.join(', ')})`);
        
        return res.status(403).json({
          error: 'Insufficient permissions',
          message: `This action requires one of the following roles: ${roles.join(', ')}`,
          requiredRoles: roles,
          yourRoles: userRoles
        });
      }
      
      // Attach roles to request for later use
      req.userRoles = userRoles;
      
      console.log(`✅ Access granted: User ${req.user.username} (${userRoles.join(', ')}) accessing ${req.path}`);
      
      next();
    } catch (error) {
      console.error('Role check error:', error);
      res.status(500).json({
        error: 'Authorization check failed',
        message: 'An error occurred while checking permissions'
      });
    }
  };
};

/**
 * Middleware: Require specific permission(s)
 * @param {Array|string} requiredPermissions - Permission name(s) required
 * @returns {Function} - Express middleware
 * 
 * @example
 * router.post('/accounts', authenticate, requirePermission('account:create'), createAccount);
 * router.delete('/users/:id', authenticate, requirePermission(['user:delete']), deleteUser);
 */
exports.requirePermission = (requiredPermissions) => {
  // Normalize to array
  const permissions = Array.isArray(requiredPermissions) ? requiredPermissions : [requiredPermissions];
  
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Authentication required',
          message: 'You must be logged in to access this resource'
        });
      }
      
      // Get user's permissions
      const userPermissions = await getUserPermissions(req.user.id);
      
      // Check if user has all required permissions
      const hasAllPermissions = permissions.every(perm => userPermissions.includes(perm));
      
      if (!hasAllPermissions) {
        const missingPermissions = permissions.filter(perm => !userPermissions.includes(perm));
        
        console.log(`❌ Permission denied: User ${req.user.username} missing permissions: ${missingPermissions.join(', ')}`);
        
        return res.status(403).json({
          error: 'Insufficient permissions',
          message: 'You do not have the required permissions for this action',
          requiredPermissions: permissions,
          missingPermissions: missingPermissions
        });
      }
      
      // Attach permissions to request
      req.userPermissions = userPermissions;
      
      next();
    } catch (error) {
      console.error('Permission check error:', error);
      res.status(500).json({
        error: 'Authorization check failed',
        message: 'An error occurred while checking permissions'
      });
    }
  };
};

/**
 * Middleware: Require either role OR permission (flexible check)
 * Useful when you want to allow access by role or specific permission
 * 
 * @param {Object} options - { roles: [], permissions: [] }
 * @returns {Function} - Express middleware
 */
exports.requireRoleOrPermission = (options) => {
  const { roles = [], permissions = [] } = options;
  
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
      }
      
      const userRoles = await getUserRoles(req.user.id);
      const userPermissions = await getUserPermissions(req.user.id);
      
      // Check roles
      const hasRole = roles.length === 0 || userRoles.some(role => roles.includes(role));
      
      // Check permissions
      const hasPermission = permissions.length === 0 || 
        permissions.every(perm => userPermissions.includes(perm));
      
      if (hasRole || hasPermission) {
        req.userRoles = userRoles;
        req.userPermissions = userPermissions;
        return next();
      }
      
      return res.status(403).json({
        error: 'Insufficient permissions',
        message: 'You do not have access to this resource'
      });
      
    } catch (error) {
      console.error('Authorization error:', error);
      res.status(500).json({ error: 'Authorization check failed' });
    }
  };
};

/**
 * Check if user has specific role (utility function, not middleware)
 * @param {number} userId - User ID
 * @param {string} roleName - Role name to check
 * @returns {Promise<boolean>}
 */
exports.hasRole = async (userId, roleName) => {
  const roles = await getUserRoles(userId);
  return roles.includes(roleName);
};

/**
 * Check if user has specific permission (utility function, not middleware)
 * @param {number} userId - User ID
 * @param {string} permissionName - Permission name to check
 * @returns {Promise<boolean>}
 */
exports.hasPermission = async (userId, permissionName) => {
  const permissions = await getUserPermissions(userId);
  return permissions.includes(permissionName);
};

// Export utility functions
exports.getUserRoles = getUserRoles;
exports.getUserPermissions = getUserPermissions;
```

## Step 2: Create Banking Models

### Create models directory

```bash
mkdir -p api/src/models
```

### `api/src/models/Account.js`

```javascript
const db = require('../config/database');

/**
 * Generate unique account number
 * Format: YYYYMMDD-XXXXXX (Date + 6 random digits)
 */
async function generateAccountNumber() {
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const random = Math.floor(100000 + Math.random() * 900000);
  const accountNumber = `${date}-${random}`;
  
  // Check if exists (very unlikely)
  const [existing] = await db.query('SELECT id FROM accounts WHERE account_number = ?', [accountNumber]);
  
  if (existing.length > 0) {
    return generateAccountNumber(); // Try again
  }
  
  return accountNumber;
}

/**
 * Create a new bank account
 */
exports.create = async (userId, branchId, accountType, initialDeposit = 0) => {
  const accountNumber = await generateAccountNumber();
  
  const [result] = await db.query(
    `INSERT INTO accounts (account_number, user_id, branch_id, account_type, balance, status) 
     VALUES (?, ?, ?, ?, ?, 'active')`,
    [accountNumber, userId, branchId, accountType, initialDeposit]
  );
  
  return {
    id: result.insertId,
    account_number: accountNumber,
    user_id: userId,
    branch_id: branchId,
    account_type: accountType,
    balance: initialDeposit,
    status: 'active'
  };
};

/**
 * Get account by ID
 */
exports.findById = async (accountId) => {
  const [rows] = await db.query(
    `SELECT a.*, u.username, u.email, b.branch_name 
     FROM accounts a
     JOIN users u ON a.user_id = u.id
     JOIN branches b ON a.branch_id = b.id
     WHERE a.id = ?`,
    [accountId]
  );
  
  return rows.length > 0 ? rows[0] : null;
};

/**
 * Get accounts by user ID
 */
exports.findByUserId = async (userId) => {
  const [rows] = await db.query(
    `SELECT a.*, b.branch_name 
     FROM accounts a
     JOIN branches b ON a.branch_id = b.id
     WHERE a.user_id = ? AND a.status != 'closed'
     ORDER BY a.created_at DESC`,
    [userId]
  );
  
  return rows;
};

/**
 * Get all accounts (admin only)
 */
exports.findAll = async (limit = 100, offset = 0) => {
  const [rows] = await db.query(
    `SELECT a.*, u.username, u.email, b.branch_name 
     FROM accounts a
     JOIN users u ON a.user_id = u.id
     JOIN branches b ON a.branch_id = b.id
     ORDER BY a.created_at DESC
     LIMIT ? OFFSET ?`,
    [limit, offset]
  );
  
  return rows;
};

/**
 * Get accounts by branch ID (for managers)
 */
exports.findByBranchId = async (branchId) => {
  const [rows] = await db.query(
    `SELECT a.*, u.username, u.email 
     FROM accounts a
     JOIN users u ON a.user_id = u.id
     WHERE a.branch_id = ? AND a.status != 'closed'
     ORDER BY a.created_at DESC`,
    [branchId]
  );
  
  return rows;
};

/**
 * Update account balance
 */
exports.updateBalance = async (accountId, newBalance) => {
  await db.query(
    'UPDATE accounts SET balance = ?, updated_at = NOW() WHERE id = ?',
    [newBalance, accountId]
  );
};

/**
 * Close account
 */
exports.close = async (accountId) => {
  await db.query(
    'UPDATE accounts SET status = ?, closed_at = NOW() WHERE id = ?',
    ['closed', accountId]
  );
};
```

### `api/src/models/Transaction.js`

```javascript
const db = require('../config/database');
const crypto = require('crypto');

/**
 * Generate unique transaction reference
 */
function generateReference() {
  return `TXN-${Date.now()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
}

/**
 * Create a transaction
 */
exports.create = async (transactionData) => {
  const {
    transactionType,
    fromAccountId,
    toAccountId,
    amount,
    description,
    initiatedBy
  } = transactionData;
  
  const reference = generateReference();
  
  const [result] = await db.query(
    `INSERT INTO transactions 
     (transaction_type, from_account_id, to_account_id, amount, description, reference_number, status, initiated_by) 
     VALUES (?, ?, ?, ?, ?, ?, 'completed', ?)`,
    [transactionType, fromAccountId, toAccountId, amount, description, reference, initiatedBy]
  );
  
  return {
    id: result.insertId,
    reference_number: reference,
    ...transactionData
  };
};

/**
 * Get transactions by account ID
 */
exports.findByAccountId = async (accountId, limit = 50) => {
  const [rows] = await db.query(
    `SELECT * FROM transactions 
     WHERE from_account_id = ? OR to_account_id = ?
     ORDER BY created_at DESC
     LIMIT ?`,
    [accountId, accountId, limit]
  );
  
  return rows;
};

/**
 * Get transactions by user ID
 */
exports.findByUserId = async (userId, limit = 50) => {
  const [rows] = await db.query(
    `SELECT t.*, 
            fa.account_number as from_account_number,
            ta.account_number as to_account_number
     FROM transactions t
     LEFT JOIN accounts fa ON t.from_account_id = fa.id
     LEFT JOIN accounts ta ON t.to_account_id = ta.id
     WHERE fa.user_id = ? OR ta.user_id = ?
     ORDER BY t.created_at DESC
     LIMIT ?`,
    [userId, userId, limit]
  );
  
  return rows;
};

/**
 * Get all transactions (admin)
 */
exports.findAll = async (limit = 100, offset = 0) => {
  const [rows] = await db.query(
    `SELECT t.*,
            fa.account_number as from_account_number,
            ta.account_number as to_account_number,
            u.username as initiated_by_username
     FROM transactions t
     LEFT JOIN accounts fa ON t.from_account_id = fa.id
     LEFT JOIN accounts ta ON t.to_account_id = ta.id
     LEFT JOIN users u ON t.initiated_by = u.id
     ORDER BY t.created_at DESC
     LIMIT ? OFFSET ?`,
    [limit, offset]
  );
  
  return rows;
};

/**
 * Get transactions by branch (for managers)
 */
exports.findByBranchId = async (branchId, limit = 100) => {
  const [rows] = await db.query(
    `SELECT DISTINCT t.*,
            fa.account_number as from_account_number,
            ta.account_number as to_account_number
     FROM transactions t
     LEFT JOIN accounts fa ON t.from_account_id = fa.id
     LEFT JOIN accounts ta ON t.to_account_id = ta.id
     WHERE fa.branch_id = ? OR ta.branch_id = ?
     ORDER BY t.created_at DESC
     LIMIT ?`,
    [branchId, branchId, limit]
  );
  
  return rows;
};
```

## Step 3: Create Banking Controllers

### `api/src/controllers/accountController.js`

```javascript
const Account = require('../models/Account');
const Transaction = require('../models/Transaction');

/**
 * Create a new bank account
 * POST /api/accounts
 * Permission: account:create
 */
exports.createAccount = async (req, res) => {
  try {
    const { account_type, initial_deposit, branch_id } = req.body;
    const userId = req.user.id;
    
    // Validate account type
    const validTypes = ['savings', 'checking', 'business'];
    if (!validTypes.includes(account_type)) {
      return res.status(400).json({
        error: 'Invalid account type',
        validTypes
      });
    }
    
    // Default to first branch if not specified
    const branchId = branch_id || 1;
    const initialDeposit = parseFloat(initial_deposit) || 0;
    
    if (initialDeposit < 0) {
      return res.status(400).json({ error: 'Initial deposit cannot be negative' });
    }
    
    // Create account
    const account = await Account.create(userId, branchId, account_type, initialDeposit);
    
    console.log(`✅ Account created: ${account.account_number} for user ${req.user.username}`);
    
    res.status(201).json({
      message: 'Account created successfully',
      account
    });
  } catch (error) {
    console.error('Create account error:', error);
    res.status(500).json({ error: 'Failed to create account' });
  }
};

/**
 * Get user's accounts
 * GET /api/accounts
 * Permission: account:read
 */
exports.getMyAccounts = async (req, res) => {
  try {
    const accounts = await Account.findByUserId(req.user.id);
    
    res.json({
      count: accounts.length,
      accounts
    });
  } catch (error) {
    console.error('Get accounts error:', error);
    res.status(500).json({ error: 'Failed to retrieve accounts' });
  }
};

/**
 * Get specific account details
 * GET /api/accounts/:id
 * Permission: account:read (own account)
 */
exports.getAccountById = async (req, res) => {
  try {
    const accountId = req.params.id;
    const account = await Account.findById(accountId);
    
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }
    
    // Check ownership (unless admin)
    const isAdmin = req.userRoles && req.userRoles.includes('admin');
    if (!isAdmin && account.user_id !== req.user.id) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You can only view your own accounts'
      });
    }
    
    res.json({ account });
  } catch (error) {
    console.error('Get account error:', error);
    res.status(500).json({ error: 'Failed to retrieve account' });
  }
};

/**
 * Get all accounts (Admin only)
 * GET /api/admin/accounts
 * Role: admin
 */
exports.getAllAccounts = async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const offset = parseInt(req.query.offset) || 0;
    
    const accounts = await Account.findAll(limit, offset);
    
    res.json({
      count: accounts.length,
      limit,
      offset,
      accounts
    });
  } catch (error) {
    console.error('Get all accounts error:', error);
    res.status(500).json({ error: 'Failed to retrieve accounts' });
  }
};

/**
 * Get branch accounts (Manager only)
 * GET /api/accounts/branch/:branchId
 * Role: manager, admin
 */
exports.getBranchAccounts = async (req, res) => {
  try {
    const branchId = req.params.branchId;
    const accounts = await Account.findByBranchId(branchId);
    
    res.json({
      branch_id: branchId,
      count: accounts.length,
      accounts
    });
  } catch (error) {
    console.error('Get branch accounts error:', error);
    res.status(500).json({ error: 'Failed to retrieve branch accounts' });
  }
};

/**
 * Close account
 * DELETE /api/accounts/:id
 * Permission: account:close (own account)
 */
exports.closeAccount = async (req, res) => {
  try {
    const accountId = req.params.id;
    const account = await Account.findById(accountId);
    
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }
    
    // Check ownership
    if (account.user_id !== req.user.id) {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You can only close your own accounts'
      });
    }
    
    // Check balance
    if (account.balance > 0) {
      return res.status(400).json({
        error: 'Cannot close account with positive balance',
        message: 'Please withdraw all funds before closing the account'
      });
    }
    
    await Account.close(accountId);
    
    console.log(`✅ Account closed: ${account.account_number} by user ${req.user.username}`);
    
    res.json({ message: 'Account closed successfully' });
  } catch (error) {
    console.error('Close account error:', error);
    res.status(500).json({ error: 'Failed to close account' });
  }
};
```

### `api/src/controllers/transactionController.js`

```javascript
const Transaction = require('../models/Transaction');
const Account = require('../models/Account');

/**
 * Get user's transactions
 * GET /api/transactions
 * Permission: transaction:read
 */
exports.getMyTransactions = async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const transactions = await Transaction.findByUserId(req.user.id, limit);
    
    res.json({
      count: transactions.length,
      transactions
    });
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ error: 'Failed to retrieve transactions' });
  }
};

/**
 * Deposit money
 * POST /api/transactions/deposit
 * Permission: transaction:create
 */
exports.deposit = async (req, res) => {
  try {
    const { account_id, amount, description } = req.body;
    
    // Validate amount
    const depositAmount = parseFloat(amount);
    if (isNaN(depositAmount) || depositAmount <= 0) {
      return res.status(400).json({ error: 'Invalid deposit amount' });
    }
    
    // Get account
    const account = await Account.findById(account_id);
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }
    
    // Check ownership
    if (account.user_id !== req.user.id) {
      return res.status(403).json({ error: 'You can only deposit to your own accounts' });
    }
    
    // Check account status
    if (account.status !== 'active') {
      return res.status(400).json({ error: 'Account is not active' });
    }
    
    // Update balance
    const newBalance = parseFloat(account.balance) + depositAmount;
    await Account.updateBalance(account_id, newBalance);
    
    // Create transaction record
    const transaction = await Transaction.create({
      transactionType: 'deposit',
      fromAccountId: null,
      toAccountId: account_id,
      amount: depositAmount,
      description: description || 'Deposit',
      initiatedBy: req.user.id
    });
    
    console.log(`✅ Deposit: $${depositAmount} to account ${account.account_number}`);
    
    res.status(201).json({
      message: 'Deposit successful',
      transaction,
      new_balance: newBalance
    });
  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({ error: 'Deposit failed' });
  }
};

/**
 * Withdraw money
 * POST /api/transactions/withdraw
 * Permission: transaction:create
 */
exports.withdraw = async (req, res) => {
  try {
    const { account_id, amount, description } = req.body;
    
    // Validate amount
    const withdrawAmount = parseFloat(amount);
    if (isNaN(withdrawAmount) || withdrawAmount <= 0) {
      return res.status(400).json({ error: 'Invalid withdrawal amount' });
    }
    
    // Get account
    const account = await Account.findById(account_id);
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }
    
    // Check ownership
    if (account.user_id !== req.user.id) {
      return res.status(403).json({ error: 'You can only withdraw from your own accounts' });
    }
    
    // Check account status
    if (account.status !== 'active') {
      return res.status(400).json({ error: 'Account is not active' });
    }
    
    // Check sufficient balance
    const currentBalance = parseFloat(account.balance);
    if (currentBalance < withdrawAmount) {
      return res.status(400).json({
        error: 'Insufficient funds',
        available: currentBalance,
        requested: withdrawAmount
      });
    }
    
    // Update balance
    const newBalance = currentBalance - withdrawAmount;
    await Account.updateBalance(account_id, newBalance);
    
    // Create transaction record
    const transaction = await Transaction.create({
      transactionType: 'withdrawal',
      fromAccountId: account_id,
      toAccountId: null,
      amount: withdrawAmount,
      description: description || 'Withdrawal',
      initiatedBy: req.user.id
    });
    
    console.log(`✅ Withdrawal: $${withdrawAmount} from account ${account.account_number}`);
    
    res.status(201).json({
      message: 'Withdrawal successful',
      transaction,
      new_balance: newBalance
    });
  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({ error: 'Withdrawal failed' });
  }
};

/**
 * Transfer money between accounts
 * POST /api/transactions/transfer
 * Permission: transaction:create
 */
exports.transfer = async (req, res) => {
  try {
    const { from_account_id, to_account_id, amount, description } = req.body;
    
    // Validate amount
    const transferAmount = parseFloat(amount);
    if (isNaN(transferAmount) || transferAmount <= 0) {
      return res.status(400).json({ error: 'Invalid transfer amount' });
    }
    
    // Get both accounts
    const fromAccount = await Account.findById(from_account_id);
    const toAccount = await Account.findById(to_account_id);
    
    if (!fromAccount || !toAccount) {
      return res.status(404).json({ error: 'One or both accounts not found' });
    }
    
    // Check ownership of source account
    if (fromAccount.user_id !== req.user.id) {
      return res.status(403).json({ error: 'You can only transfer from your own accounts' });
    }
    
    // Check account status
    if (fromAccount.status !== 'active' || toAccount.status !== 'active') {
      return res.status(400).json({ error: 'One or both accounts are not active' });
    }
    
    // Check sufficient balance
    const currentBalance = parseFloat(fromAccount.balance);
    if (currentBalance < transferAmount) {
      return res.status(400).json({
        error: 'Insufficient funds',
        available: currentBalance,
        requested: transferAmount
      });
    }
    
    // Perform transfer (update both balances)
    const newFromBalance = currentBalance - transferAmount;
    const newToBalance = parseFloat(toAccount.balance) + transferAmount;
    
    await Account.updateBalance(from_account_id, newFromBalance);
    await Account.updateBalance(to_account_id, newToBalance);
    
    // Create transaction record
    const transaction = await Transaction.create({
      transactionType: 'transfer',
      fromAccountId: from_account_id,
      toAccountId: to_account_id,
      amount: transferAmount,
      description: description || 'Transfer',
      initiatedBy: req.user.id
    });
    
    console.log(`✅ Transfer: $${transferAmount} from ${fromAccount.account_number} to ${toAccount.account_number}`);
    
    res.status(201).json({
      message: 'Transfer successful',
      transaction,
      from_account_new_balance: newFromBalance,
      to_account_new_balance: newToBalance
    });
  } catch (error) {
    console.error('Transfer error:', error);
    res.status(500).json({ error: 'Transfer failed' });
  }
};

/**
 * Get all transactions (Admin only)
 * GET /api/admin/transactions
 * Role: admin
 */
exports.getAllTransactions = async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const offset = parseInt(req.query.offset) || 0;
    
    const transactions = await Transaction.findAll(limit, offset);
    
    res.json({
      count: transactions.length,
      limit,
      offset,
      transactions
    });
  } catch (error) {
    console.error('Get all transactions error:', error);
    res.status(500).json({ error: 'Failed to retrieve transactions' });
  }
};

/**
 * Get branch transactions (Manager only)
 * GET /api/transactions/branch/:branchId
 * Role: manager, admin
 */
exports.getBranchTransactions = async (req, res) => {
  try {
    const branchId = req.params.branchId;
    const limit = parseInt(req.query.limit) || 100;
    
    const transactions = await Transaction.findByBranchId(branchId, limit);
    
    res.json({
      branch_id: branchId,
      count: transactions.length,
      transactions
    });
  } catch (error) {
    console.error('Get branch transactions error:', error);
    res.status(500).json({ error: 'Failed to retrieve branch transactions' });
  }
};
```

## Step 4: Create Admin Controller

### `api/src/controllers/adminController.js`

```javascript
const db = require('../config/database');
const authService = require('../services/authService');

/**
 * Get all users
 * GET /api/admin/users
 * Role: admin
 */
exports.getAllUsers = async (req, res) => {
  try {
    const [users] = await db.query(
      `SELECT u.id, u.username, u.email, u.first_name, u.last_name, 
              u.auth_provider, u.is_active, u.created_at, u.last_login_at,
              GROUP_CONCAT(r.name) as roles
       FROM users u
       LEFT JOIN user_roles ur ON u.id = ur.user_id
       LEFT JOIN roles r ON ur.role_id = r.id
       GROUP BY u.id
       ORDER BY u.created_at DESC`
    );
    
    res.json({
      count: users.length,
      users
    });
  } catch (error) {
    console.error('Get all users error:', error);
    res.status(500).json({ error: 'Failed to retrieve users' });
  }
};

/**
 * Assign role to user
 * POST /api/admin/users/:id/roles
 * Role: admin
 */
exports.assignRole = async (req, res) => {
  try {
    const userId = req.params.id;
    const { role_name } = req.body;
    
    // Validate role exists
    const [roles] = await db.query('SELECT id FROM roles WHERE name = ?', [role_name]);
    if (roles.length === 0) {
      return res.status(400).json({
        error: 'Invalid role',
        validRoles: ['admin', 'manager', 'customer']
      });
    }
    
    const roleId = roles[0].id;
    
    // Check if user already has this role
    const [existing] = await db.query(
      'SELECT * FROM user_roles WHERE user_id = ? AND role_id = ?',
      [userId, roleId]
    );
    
    if (existing.length > 0) {
      return res.status(400).json({ error: 'User already has this role' });
    }
    
    // Assign role
    await db.query(
      'INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES (?, ?, ?)',
      [userId, roleId, req.user.id]
    );
    
    console.log(`✅ Role assigned: ${role_name} to user ID ${userId} by admin ${req.user.username}`);
    
    res.json({
      message: 'Role assigned successfully',
      user_id: userId,
      role: role_name
    });
  } catch (error) {
    console.error('Assign role error:', error);
    res.status(500).json({ error: 'Failed to assign role' });
  }
};

/**
 * Remove role from user
 * DELETE /api/admin/users/:id/roles/:roleName
 * Role: admin
 */
exports.removeRole = async (req, res) => {
  try {
    const userId = req.params.id;
    const roleName = req.params.roleName;
    
    // Get role ID
    const [roles] = await db.query('SELECT id FROM roles WHERE name = ?', [roleName]);
    if (roles.length === 0) {
      return res.status(404).json({ error: 'Role not found' });
    }
    
    // Remove role
    const [result] = await db.query(
      'DELETE FROM user_roles WHERE user_id = ? AND role_id = ?',
      [userId, roles[0].id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User does not have this role' });
    }
    
    console.log(`✅ Role removed: ${roleName} from user ID ${userId} by admin ${req.user.username}`);
    
    res.json({ message: 'Role removed successfully' });
  } catch (error) {
    console.error('Remove role error:', error);
    res.status(500).json({ error: 'Failed to remove role' });
  }
};

/**
 * Get login attempts
 * GET /api/admin/login-attempts
 * Role: admin
 */
exports.getLoginAttempts = async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const [attempts] = await db.query(
      'SELECT * FROM login_attempts ORDER BY attempted_at DESC LIMIT ?',
      [limit]
    );
    
    res.json({
      count: attempts.length,
      attempts
    });
  } catch (error) {
    console.error('Get login attempts error:', error);
    res.status(500).json({ error: 'Failed to retrieve login attempts' });
  }
};

/**
 * Get locked accounts
 * GET /api/admin/locked-accounts
 * Role: admin
 */
exports.getLockedAccounts = async (req, res) => {
  try {
    const [lockouts] = await db.query(
      `SELECT al.*, u.username, u.email
       FROM account_lockouts al
       JOIN users u ON al.user_id = u.id
       WHERE al.is_unlocked = FALSE
       ORDER BY al.locked_at DESC`
    );
    
    res.json({
      count: lockouts.length,
      lockouts
    });
  } catch (error) {
    console.error('Get locked accounts error:', error);
    res.status(500).json({ error: 'Failed to retrieve locked accounts' });
  }
};

/**
 * Unlock user account
 * POST /api/admin/users/:id/unlock
 * Role: admin
 */
exports.unlockAccount = async (req, res) => {
  try {
    const userId = req.params.id;
    
    // Update account_lockouts
    const [result] = await db.query(
      `UPDATE account_lockouts 
       SET is_unlocked = TRUE, unlocked_at = NOW(), unlocked_by = ?
       WHERE user_id = ? AND is_unlocked = FALSE`,
      [req.user.id, userId]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'No locked account found for this user' });
    }
    
    console.log(`✅ Account unlocked: User ID ${userId} by admin ${req.user.username}`);
    
    res.json({ message: 'Account unlocked successfully' });
  } catch (error) {
    console.error('Unlock account error:', error);
    res.status(500).json({ error: 'Failed to unlock account' });
  }
};
```

## Step 5: Create Routes with RBAC

### `api/src/routes/accounts.js`

```javascript
const express = require('express');
const accountController = require('../controllers/accountController');
const { authenticate } = require('../middleware/auth');
const { requireRole, requirePermission } = require('../middleware/rbac');

const router = express.Router();

// Customer routes - require authentication and customer role
router.post('/', 
  authenticate, 
  requirePermission('account:create'),
  accountController.createAccount
);

router.get('/', 
  authenticate, 
  requirePermission('account:read'),
  accountController.getMyAccounts
);

router.get('/:id', 
  authenticate, 
  requirePermission('account:read'),
  accountController.getAccountById
);

router.delete('/:id', 
  authenticate, 
  requirePermission('account:close'),
  accountController.closeAccount
);

// Manager routes - view branch accounts
router.get('/branch/:branchId', 
  authenticate, 
  requireRole(['manager', 'admin']),
  accountController.getBranchAccounts
);

module.exports = router;
```

### `api/src/routes/transactions.js`

```javascript
const express = require('express');
const transactionController = require('../controllers/transactionController');
const { authenticate } = require('../middleware/auth');
const { requireRole, requirePermission } = require('../middleware/rbac');

const router = express.Router();

// Customer routes
router.get('/', 
  authenticate, 
  requirePermission('transaction:read'),
  transactionController.getMyTransactions
);

router.post('/deposit', 
  authenticate, 
  requirePermission('transaction:create'),
  transactionController.deposit
);

router.post('/withdraw', 
  authenticate, 
  requirePermission('transaction:create'),
  transactionController.withdraw
);

router.post('/transfer', 
  authenticate, 
  requirePermission('transaction:create'),
  transactionController.transfer
);

// Manager routes
router.get('/branch/:branchId', 
  authenticate, 
  requireRole(['manager', 'admin']),
  transactionController.getBranchTransactions
);

module.exports = router;
```

### `api/src/routes/admin.js`

```javascript
const express = require('express');
const adminController = require('../controllers/adminController');
const accountController = require('../controllers/accountController');
const transactionController = require('../controllers/transactionController');
const { authenticate } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');

const router = express.Router();

// All admin routes require admin role
router.use(authenticate);
router.use(requireRole('admin'));

// User management
router.get('/users', adminController.getAllUsers);
router.post('/users/:id/roles', adminController.assignRole);
router.delete('/users/:id/roles/:roleName', adminController.removeRole);
router.post('/users/:id/unlock', adminController.unlockAccount);

// View all accounts and transactions
router.get('/accounts', accountController.getAllAccounts);
router.get('/transactions', transactionController.getAllTransactions);

// Security monitoring
router.get('/login-attempts', adminController.getLoginAttempts);
router.get('/locked-accounts', adminController.getLockedAccounts);

module.exports = router;
```

### Update `api/src/routes/index.js`

```javascript
const express = require('express');
const healthController = require('../controllers/healthController');
const authRoutes = require('./auth');
const accountRoutes = require('./accounts');
const transactionRoutes = require('./transactions');
const adminRoutes = require('./admin');

const router = express.Router();

// Health check
router.get('/health', healthController.healthCheck);

// Authentication routes
router.use('/auth', authRoutes);

// Banking routes
router.use('/accounts', accountRoutes);
router.use('/transactions', transactionRoutes);

// Admin routes
router.use('/admin', adminRoutes);

module.exports = router;
```

## Step 6: Test RBAC

### 1. Restart API

```bash
docker-compose restart api
docker-compose logs -f api
```

### 2. Create Test Users with Different Roles

```bash
# Register regular customer
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice_customer",
    "email": "alice@example.com",
    "password": "SecurePass123!",
    "first_name": "Alice"
  }'

# Register manager
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "bob_manager",
    "email": "bob@example.com",
    "password": "SecurePass123!",
    "first_name": "Bob"
  }'

# Register admin
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "carol_admin",
    "email": "carol@example.com",
    "password": "SecurePass123!",
    "first_name": "Carol"
  }'
```

### 3. Manually Assign Roles in Database

```bash
docker exec -it banking-mysql mysql -u root -p
# Password: rootpass123

USE banking_db;

-- Make Bob a manager (user_id=2, assuming registration order)
INSERT INTO user_roles (user_id, role_id) 
SELECT 2, id FROM roles WHERE name = 'manager';

-- Make Carol an admin (user_id=3)
INSERT INTO user_roles (user_id, role_id) 
SELECT 3, id FROM roles WHERE name = 'admin';

-- Verify
SELECT u.username, r.name as role 
FROM users u
JOIN user_roles ur ON u.id = ur.user_id
JOIN roles r ON ur.role_id = r.id;

EXIT;
```

### 4. Login as Customer (Alice)

```bash
# Login
ALICE_TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice_customer","password":"SecurePass123!"}' \
  | jq -r '.accessToken')

echo "Alice Token: $ALICE_TOKEN"
```

### 5. Test Customer Permissions

```bash
# Create account (Should work - customers can create accounts)
curl -X POST http://localhost:3000/api/accounts \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_type": "savings",
    "initial_deposit": 1000,
    "branch_id": 1
  }'

# Get my accounts (Should work)
curl -X GET http://localhost:3000/api/accounts \
  -H "Authorization: Bearer $ALICE_TOKEN"

# Try to access admin endpoint (Should FAIL with 403)
curl -X GET http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer $ALICE_TOKEN"
```

Expected error:
```json
{
  "error": "Insufficient permissions",
  "message": "This action requires one of the following roles: admin",
  "requiredRoles": ["admin"],
  "yourRoles": ["customer"]
}
```

### 6. Login as Manager (Bob)

```bash
# Login
BOB_TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"bob_manager","password":"SecurePass123!"}' \
  | jq -r '.accessToken')
```

### 7. Test Manager Permissions

```bash
# View branch accounts (Should work)
curl -X GET http://localhost:3000/api/accounts/branch/1 \
  -H "Authorization: Bearer $BOB_TOKEN"

# Try to assign roles (Should FAIL - only admins can)
curl -X POST http://localhost:3000/api/admin/users/1/roles \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role_name": "manager"}'
```

### 8. Login as Admin (Carol)

```bash
# Login
CAROL_TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"carol_admin","password":"SecurePass123!"}' \
  | jq -r '.accessToken')
```

### 9. Test Admin Permissions

```bash
# View all users (Should work)
curl -X GET http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer $CAROL_TOKEN"

# View all accounts (Should work)
curl -X GET http://localhost:3000/api/admin/accounts \
  -H "Authorization: Bearer $CAROL_TOKEN"

# Assign role to Alice (Should work)
curl -X POST http://localhost:3000/api/admin/users/1/roles \
  -H "Authorization: Bearer $CAROL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role_name": "manager"}'

# View login attempts (Should work)
curl -X GET http://localhost:3000/api/admin/login-attempts \
  -H "Authorization: Bearer $CAROL_TOKEN"
```

## Understanding RBAC

### Role Hierarchy

```
Admin (Full Access)
  │
  ├─ All permissions
  ├─ User management
  ├─ Role assignment
  └─ Security monitoring

Manager (Branch Access)
  │
  ├─ View branch accounts
  ├─ View branch transactions
  └─ Create own accounts

Customer (Personal Access)
  │
  ├─ Create accounts
  ├─ View own accounts
  ├─ Create transactions
  └─ View own transactions
```

### Permission Matrix

| Action | Customer | Manager | Admin |
|--------|----------|---------|-------|
| Create own account | ✅ | ✅ | ✅ |
| View own accounts | ✅ | ✅ | ✅ |
| View branch accounts | ❌ | ✅ | ✅ |
| View all accounts | ❌ | ❌ | ✅ |
| Create transaction | ✅ | ✅ | ✅ |
| View branch transactions | ❌ | ✅ | ✅ |
| View all transactions | ❌ | ❌ | ✅ |
| Assign roles | ❌ | ❌ | ✅ |
| Unlock accounts | ❌ | ❌ | ✅ |
| View audit logs | ❌ | ❌ | ✅ |

## Testing Your Understanding

Before moving to Part 5, ensure you can:

1. ✅ Create users with different roles
2. ✅ Test permission checks work correctly
3. ✅ Understand role-based access control
4. ✅ Explain difference between roles and permissions
5. ✅ Demonstrate 403 Forbidden errors
6. ✅ Use admin endpoints to manage users

## Discussion Questions

1. **RBAC vs Individual Permissions**
   - Why group permissions into roles?
   - What if a user needs custom permissions?

2. **Role Assignment**
   - Who should be able to assign roles?
   - Should users have multiple roles?
   - How to prevent privilege escalation?

3. **Manager Role**
   - Is branch-level access sufficient?
   - What if manager changes branches?
   - Should managers approve customer actions?

4. **Security Implications**
   - What happens if admin token is stolen?
   - How to audit role changes?
   - Should there be a super-admin role?

## Next Steps

✅ You've completed Part 4!

You now have:
- Role-Based Access Control
- Three distinct roles (customer, manager, admin)
- Protected banking endpoints
- Permission checking middleware

In **Part 5**, we'll add:
- Attribute-Based Access Control (ABAC)
- Fine-grained access rules
- Resource ownership checks
- Context-aware authorization

Continue to: [Part 5: ABAC Authorization](./5_abac_authorization.md)

## Additional Resources

- [NIST RBAC Model](https://csrc.nist.gov/projects/role-based-access-control)
- [RBAC vs ABAC](https://www.okta.com/identity-101/role-based-access-control-vs-attribute-based-access-control/)
- [Express.js Middleware](https://expressjs.com/en/guide/using-middleware.html)
- [OAuth RBAC](https://auth0.com/docs/manage-users/access-control/rbac)
