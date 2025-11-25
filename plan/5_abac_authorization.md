# Part 5: Attribute-Based Access Control (ABAC)

## Learning Objectives

By the end of this part, you will:
- ✅ Understand Attribute-Based Access Control (ABAC) concepts
- ✅ Implement policy-based authorization
- ✅ Create context-aware access rules
- ✅ Combine RBAC with ABAC for fine-grained control
- ✅ Handle complex authorization scenarios

## Overview

In Part 5, we'll enhance our authorization system with **Attribute-Based Access Control (ABAC)**. While RBAC uses roles, ABAC uses attributes of users, resources, and context to make authorization decisions.

## ABAC vs RBAC

### RBAC (Part 4)
```
User has Role → Role has Permissions → Allow/Deny
Simple, but rigid
```

### ABAC (Part 5)
```
User attributes + Resource attributes + Context → Policy evaluation → Allow/Deny
Complex, but flexible
```

## ABAC Concepts

### Attributes

**Subject Attributes** (Who)
- User ID
- Roles
- Branch ID
- Department
- Account type
- Daily transaction limit

**Resource Attributes** (What)
- Account owner ID
- Account branch
- Account status
- Transaction amount

**Environment Attributes** (When/Where)
- Time of day
- IP address
- Day of week
- Geographic location

### Policy Examples

1. **Account Ownership**
   ```
   ALLOW if user.id == account.owner_id
   ```

2. **Branch Access**
   ```
   ALLOW if user.branch_id == account.branch_id AND user.role == 'manager'
   ```

3. **Transaction Limits**
   ```
   ALLOW if transaction.amount <= user.daily_limit AND transaction.type == 'transfer'
   ```

4. **Time-based**
   ```
   ALLOW if current_time BETWEEN '09:00' AND '17:00' AND user.account_type == 'business'
   ```

## Architecture

```
┌─────────────────────────────────────────────────┐
│         Authorization Request                    │
│   User wants to transfer $10,000                 │
└────────────────┬────────────────────────────────┘
                 │
                 ▼
    ┌────────────────────────┐
    │   Load Attributes      │
    │   - User: daily_limit  │
    │   - Account: balance   │
    │   - Context: time      │
    └───────────┬────────────┘
                │
                ▼
    ┌────────────────────────┐
    │   Evaluate Policies    │
    │   1. Ownership check   │
    │   2. Limit check       │
    │   3. Time check        │
    │   4. Branch check      │
    └───────────┬────────────┘
                │
        ┌───────┴───────┐
        │               │
    ALL PASS       ANY FAIL
        │               │
        ▼               ▼
    ALLOW           DENY
```

## Step 1: Set User Attributes

### Add attributes to users in database

```bash
docker exec -it banking-mysql mysql -u root -p
# Password: rootpass123

USE banking_db;

-- Add attributes for Alice (customer at branch 1, $1000 daily limit)
INSERT INTO user_attributes (user_id, attribute_key, attribute_value) VALUES
(1, 'branch_id', '1'),
(1, 'daily_transfer_limit', '1000'),
(1, 'account_type', 'personal');

-- Add attributes for Bob (manager at branch 1, higher limit)
INSERT INTO user_attributes (user_id, attribute_key, attribute_value) VALUES
(2, 'branch_id', '1'),
(2, 'daily_transfer_limit', '10000'),
(2, 'account_type', 'business');

-- Add attributes for Carol (admin, no limits)
INSERT INTO user_attributes (user_id, attribute_key, attribute_value) VALUES
(3, 'branch_id', '1'),
(3, 'daily_transfer_limit', '999999'),
(3, 'account_type', 'admin');

-- Verify
SELECT u.username, ua.attribute_key, ua.attribute_value
FROM users u
JOIN user_attributes ua ON u.id = ua.user_id
ORDER BY u.id, ua.attribute_key;

EXIT;
```

## Step 2: Create ABAC Service

### `api/src/services/abacService.js`

```javascript
const db = require('../config/database');

/**
 * Get user attributes
 * @param {number} userId - User ID
 * @returns {Promise<Object>} - Attributes as key-value object
 */
exports.getUserAttributes = async (userId) => {
  const [rows] = await db.query(
    'SELECT attribute_key, attribute_value FROM user_attributes WHERE user_id = ?',
    [userId]
  );
  
  // Convert to object
  const attributes = {};
  rows.forEach(row => {
    attributes[row.attribute_key] = row.attribute_value;
  });
  
  return attributes;
};

/**
 * Set user attribute
 * @param {number} userId - User ID
 * @param {string} key - Attribute key
 * @param {string} value - Attribute value
 */
exports.setUserAttribute = async (userId, key, value) => {
  await db.query(
    `INSERT INTO user_attributes (user_id, attribute_key, attribute_value) 
     VALUES (?, ?, ?) 
     ON DUPLICATE KEY UPDATE attribute_value = ?`,
    [userId, key, value, value]
  );
};

/**
 * Policy: Check if user owns resource
 * @param {number} userId - User ID
 * @param {Object} resource - Resource with owner_id or user_id
 * @returns {boolean}
 */
exports.policyOwnership = (userId, resource) => {
  const ownerId = resource.owner_id || resource.user_id;
  return userId === ownerId;
};

/**
 * Policy: Check if user is in same branch as resource
 * @param {Object} userAttributes - User attributes
 * @param {Object} resource - Resource with branch_id
 * @returns {boolean}
 */
exports.policyBranchAccess = (userAttributes, resource) => {
  if (!userAttributes.branch_id || !resource.branch_id) {
    return false;
  }
  return userAttributes.branch_id === resource.branch_id.toString();
};

/**
 * Policy: Check if amount is within daily limit
 * @param {Object} userAttributes - User attributes
 * @param {number} amount - Transaction amount
 * @param {number} todayTotal - Total transferred today
 * @returns {boolean}
 */
exports.policyDailyLimit = (userAttributes, amount, todayTotal = 0) => {
  const limit = parseFloat(userAttributes.daily_transfer_limit || 0);
  if (limit === 0) return false; // No limit set
  
  const newTotal = todayTotal + amount;
  return newTotal <= limit;
};

/**
 * Policy: Check if action is within business hours
 * @param {string} startHour - Start hour (e.g., '09:00')
 * @param {string} endHour - End hour (e.g., '17:00')
 * @returns {boolean}
 */
exports.policyBusinessHours = (startHour = '00:00', endHour = '23:59') => {
  const now = new Date();
  const currentHour = now.getHours();
  const currentMinute = now.getMinutes();
  const currentTime = currentHour * 60 + currentMinute;
  
  const [startH, startM] = startHour.split(':').map(Number);
  const [endH, endM] = endHour.split(':').map(Number);
  const startTime = startH * 60 + startM;
  const endTime = endH * 60 + endM;
  
  return currentTime >= startTime && currentTime <= endTime;
};

/**
 * Policy: Check if user can access account
 * Combines multiple policies:
 * 1. Owner can always access
 * 2. Manager from same branch can access
 * 3. Admin can access everything
 * 
 * @param {Object} user - User object with id
 * @param {Array} userRoles - User roles
 * @param {Object} userAttributes - User attributes
 * @param {Object} account - Account object
 * @returns {boolean}
 */
exports.canAccessAccount = (user, userRoles, userAttributes, account) => {
  // Policy 1: Ownership
  if (exports.policyOwnership(user.id, account)) {
    return true;
  }
  
  // Policy 2: Admin access
  if (userRoles.includes('admin')) {
    return true;
  }
  
  // Policy 3: Manager from same branch
  if (userRoles.includes('manager') && exports.policyBranchAccess(userAttributes, account)) {
    return true;
  }
  
  return false;
};

/**
 * Policy: Check if user can perform transaction
 * @param {Object} user - User object
 * @param {Object} userAttributes - User attributes
 * @param {Array} userRoles - User roles
 * @param {Object} account - Account object
 * @param {number} amount - Transaction amount
 * @param {number} todayTotal - Total transferred today
 * @returns {Object} - { allowed: boolean, reason: string }
 */
exports.canPerformTransaction = async (user, userAttributes, userRoles, account, amount, todayTotal = 0) => {
  // Check ownership
  if (!exports.policyOwnership(user.id, account)) {
    return {
      allowed: false,
      reason: 'You can only transact from your own accounts'
    };
  }
  
  // Admin bypass all limits
  if (userRoles.includes('admin')) {
    return { allowed: true };
  }
  
  // Check daily limit
  if (!exports.policyDailyLimit(userAttributes, amount, todayTotal)) {
    const limit = parseFloat(userAttributes.daily_transfer_limit || 0);
    return {
      allowed: false,
      reason: `Transaction exceeds daily limit. Limit: $${limit}, Today's total: $${todayTotal}, Requested: $${amount}`
    };
  }
  
  // Check business hours for large transactions (over $5000)
  if (amount > 5000 && !exports.policyBusinessHours('09:00', '17:00')) {
    return {
      allowed: false,
      reason: 'Large transactions (>$5000) are only allowed during business hours (9 AM - 5 PM)'
    };
  }
  
  return { allowed: true };
};

/**
 * Get total transferred today by user
 * @param {number} userId - User ID
 * @returns {Promise<number>} - Total amount transferred today
 */
exports.getTodayTransferTotal = async (userId) => {
  const [rows] = await db.query(
    `SELECT COALESCE(SUM(amount), 0) as total
     FROM transactions t
     JOIN accounts a ON t.from_account_id = a.id
     WHERE a.user_id = ? 
       AND t.transaction_type = 'transfer'
       AND t.status = 'completed'
       AND DATE(t.created_at) = CURDATE()`,
    [userId]
  );
  
  return parseFloat(rows[0].total);
};
```

## Step 3: Create ABAC Middleware

### `api/src/middleware/abac.js`

```javascript
const abacService = require('../services/abacService');
const { getUserRoles } = require('./rbac');
const Account = require('../models/Account');

/**
 * Middleware: Check account access with ABAC
 * Attaches account to req.account if authorized
 */
exports.checkAccountAccess = async (req, res, next) => {
  try {
    const accountId = req.params.id || req.body.account_id;
    
    if (!accountId) {
      return res.status(400).json({ error: 'Account ID required' });
    }
    
    // Get account
    const account = await Account.findById(accountId);
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }
    
    // Get user attributes and roles
    const userAttributes = await abacService.getUserAttributes(req.user.id);
    const userRoles = await getUserRoles(req.user.id);
    
    // Check access using ABAC policy
    const canAccess = abacService.canAccessAccount(
      req.user,
      userRoles,
      userAttributes,
      account
    );
    
    if (!canAccess) {
      console.log(`❌ ABAC: Access denied to account ${account.account_number} for user ${req.user.username}`);
      return res.status(403).json({
        error: 'Access denied',
        message: 'You do not have permission to access this account',
        policies: {
          ownership: abacService.policyOwnership(req.user.id, account),
          branch_access: abacService.policyBranchAccess(userAttributes, account),
          is_admin: userRoles.includes('admin')
        }
      });
    }
    
    // Attach to request for controller use
    req.account = account;
    req.userAttributes = userAttributes;
    req.userRoles = userRoles;
    
    console.log(`✅ ABAC: Access granted to account ${account.account_number} for user ${req.user.username}`);
    
    next();
  } catch (error) {
    console.error('ABAC check error:', error);
    res.status(500).json({ error: 'Authorization check failed' });
  }
};

/**
 * Middleware: Check transaction permissions with ABAC
 * Validates transaction amount against daily limits
 */
exports.checkTransactionPermission = async (req, res, next) => {
  try {
    const { from_account_id, amount } = req.body;
    const transactionAmount = parseFloat(amount);
    
    if (isNaN(transactionAmount) || transactionAmount <= 0) {
      return res.status(400).json({ error: 'Invalid transaction amount' });
    }
    
    // Get account
    const account = await Account.findById(from_account_id);
    if (!account) {
      return res.status(404).json({ error: 'Account not found' });
    }
    
    // Get user context
    const userAttributes = await abacService.getUserAttributes(req.user.id);
    const userRoles = await getUserRoles(req.user.id);
    const todayTotal = await abacService.getTodayTransferTotal(req.user.id);
    
    // Check transaction permission
    const result = await abacService.canPerformTransaction(
      req.user,
      userAttributes,
      userRoles,
      account,
      transactionAmount,
      todayTotal
    );
    
    if (!result.allowed) {
      console.log(`❌ ABAC: Transaction denied for user ${req.user.username}: ${result.reason}`);
      return res.status(403).json({
        error: 'Transaction not allowed',
        reason: result.reason,
        details: {
          daily_limit: userAttributes.daily_transfer_limit,
          today_total: todayTotal,
          requested_amount: transactionAmount,
          remaining: parseFloat(userAttributes.daily_transfer_limit || 0) - todayTotal
        }
      });
    }
    
    // Attach context to request
    req.account = account;
    req.userAttributes = userAttributes;
    req.todayTotal = todayTotal;
    
    console.log(`✅ ABAC: Transaction approved for user ${req.user.username} ($${transactionAmount})`);
    
    next();
  } catch (error) {
    console.error('ABAC transaction check error:', error);
    res.status(500).json({ error: 'Authorization check failed' });
  }
};

/**
 * Middleware: Business hours check
 * @param {string} startHour - Start hour (default: 09:00)
 * @param {string} endHour - End hour (default: 17:00)
 */
exports.requireBusinessHours = (startHour = '09:00', endHour = '17:00') => {
  return (req, res, next) => {
    if (!abacService.policyBusinessHours(startHour, endHour)) {
      return res.status(403).json({
        error: 'Outside business hours',
        message: `This action is only available between ${startHour} and ${endHour}`,
        current_time: new Date().toLocaleTimeString()
      });
    }
    next();
  };
};
```

## Step 4: Update Transaction Controller with ABAC

Update `api/src/controllers/transactionController.js` to use ABAC:

```javascript
// Add to top of file
const abacService = require('../services/abacService');

// Update the transfer function to use req.account and req.userAttributes from ABAC middleware
exports.transfer = async (req, res) => {
  try {
    const { from_account_id, to_account_id, amount, description } = req.body;
    const transferAmount = parseFloat(amount);
    
    // Account and permissions already checked by ABAC middleware
    const fromAccount = req.account;
    
    // Get destination account
    const toAccount = await Account.findById(to_account_id);
    if (!toAccount) {
      return res.status(404).json({ error: 'Destination account not found' });
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
    
    // Perform transfer
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
    console.log(`   Daily total: $${req.todayTotal + transferAmount} / $${req.userAttributes.daily_transfer_limit}`);
    
    res.status(201).json({
      message: 'Transfer successful',
      transaction,
      from_account_new_balance: newFromBalance,
      to_account_new_balance: newToBalance,
      daily_limit_remaining: parseFloat(req.userAttributes.daily_transfer_limit || 0) - (req.todayTotal + transferAmount)
    });
  } catch (error) {
    console.error('Transfer error:', error);
    res.status(500).json({ error: 'Transfer failed' });
  }
};
```

## Step 5: Update Routes with ABAC

Update `api/src/routes/accounts.js`:

```javascript
const express = require('express');
const accountController = require('../controllers/accountController');
const { authenticate } = require('../middleware/auth');
const { requireRole, requirePermission } = require('../middleware/rbac');
const { checkAccountAccess } = require('../middleware/abac');

const router = express.Router();

// Customer routes
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

// ABAC: Check account access before retrieving
router.get('/:id', 
  authenticate, 
  requirePermission('account:read'),
  checkAccountAccess,  // ABAC middleware
  accountController.getAccountById
);

// ABAC: Check account access before closing
router.delete('/:id', 
  authenticate, 
  requirePermission('account:close'),
  checkAccountAccess,  // ABAC middleware
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

Update `api/src/routes/transactions.js`:

```javascript
const express = require('express');
const transactionController = require('../controllers/transactionController');
const { authenticate } = require('../middleware/auth');
const { requireRole, requirePermission } = require('../middleware/rbac');
const { checkAccountAccess, checkTransactionPermission } = require('../middleware/abac');

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
  checkAccountAccess,  // ABAC: Check account ownership
  transactionController.deposit
);

router.post('/withdraw', 
  authenticate, 
  requirePermission('transaction:create'),
  checkAccountAccess,  // ABAC: Check account ownership
  transactionController.withdraw
);

// ABAC: Check transaction permission (daily limits, business hours, etc.)
router.post('/transfer', 
  authenticate, 
  requirePermission('transaction:create'),
  checkTransactionPermission,  // ABAC middleware with limit checks
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

## Step 6: Test ABAC Policies

### 1. Login as Alice (Customer)

```bash
ALICE_TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice_customer","password":"SecurePass123!"}' \
  | jq -r '.accessToken')
```

### 2. Create Alice's Account

```bash
# Create account with initial deposit
ALICE_ACCOUNT=$(curl -s -X POST http://localhost:3000/api/accounts \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_type": "savings",
    "initial_deposit": 5000,
    "branch_id": 1
  }' | jq -r '.account.id')

echo "Alice's Account ID: $ALICE_ACCOUNT"
```

### 3. Create Bob's Account

```bash
BOB_TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"bob_manager","password":"SecurePass123!"}' \
  | jq -r '.accessToken')

BOB_ACCOUNT=$(curl -s -X POST http://localhost:3000/api/accounts \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_type": "checking",
    "initial_deposit": 10000,
    "branch_id": 1
  }' | jq -r '.account.id')

echo "Bob's Account ID: $BOB_ACCOUNT"
```

### 4. Test Ownership Policy

```bash
# Alice tries to view her own account (Should work)
curl -X GET "http://localhost:3000/api/accounts/$ALICE_ACCOUNT" \
  -H "Authorization: Bearer $ALICE_TOKEN"

# Alice tries to view Bob's account (Should FAIL - not owner)
curl -X GET "http://localhost:3000/api/accounts/$BOB_ACCOUNT" \
  -H "Authorization: Bearer $ALICE_TOKEN"
```

### 5. Test Daily Limit Policy

```bash
# Alice transfers $500 (Should work - under $1000 limit)
curl -X POST http://localhost:3000/api/transactions/transfer \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"from_account_id\": $ALICE_ACCOUNT,
    \"to_account_id\": $BOB_ACCOUNT,
    \"amount\": 500,
    \"description\": \"Test transfer 1\"
  }"

# Alice transfers $600 more (Should FAIL - exceeds $1000 daily limit)
curl -X POST http://localhost:3000/api/transactions/transfer \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"from_account_id\": $ALICE_ACCOUNT,
    \"to_account_id\": $BOB_ACCOUNT,
    \"amount\": 600,
    \"description\": \"Test transfer 2\"
  }"
```

Expected error:
```json
{
  "error": "Transaction not allowed",
  "reason": "Transaction exceeds daily limit. Limit: $1000, Today's total: $500, Requested: $600",
  "details": {
    "daily_limit": "1000",
    "today_total": 500,
    "requested_amount": 600,
    "remaining": 500
  }
}
```

### 6. Test Business Hours Policy (Large Transaction)

```bash
# Try to transfer $6000 (large transaction)
# This will fail outside 9 AM - 5 PM
curl -X POST http://localhost:3000/api/transactions/transfer \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"from_account_id\": $BOB_ACCOUNT,
    \"to_account_id\": $ALICE_ACCOUNT,
    \"amount\": 6000,
    \"description\": \"Large transfer\"
  }"
```

### 7. Test Branch Manager Access

```bash
# Bob (manager at branch 1) can view Alice's account (same branch)
curl -X GET "http://localhost:3000/api/accounts/$ALICE_ACCOUNT" \
  -H "Authorization: Bearer $BOB_TOKEN"

# This works because Bob is a manager and Alice's account is in his branch
```

### 8. Test Admin Bypass

```bash
CAROL_TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"carol_admin","password":"SecurePass123!"}' \
  | jq -r '.accessToken')

# Carol (admin) can transfer any amount (no limits)
curl -X POST http://localhost:3000/api/transactions/transfer \
  -H "Authorization: Bearer $CAROL_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"from_account_id\": $BOB_ACCOUNT,
    \"to_account_id\": $ALICE_ACCOUNT,
    \"amount\": 50000,
    \"description\": \"Admin transfer - no limits\"
  }"
```

## Understanding ABAC

### RBAC + ABAC Combination

```
┌──────────────────────────────────────────────┐
│            Authorization Check               │
├──────────────────────────────────────────────┤
│  1. RBAC: Does user have required role?     │
│     ↓ YES                                    │
│  2. ABAC: Check contextual policies          │
│     - Ownership                              │
│     - Branch access                          │
│     - Daily limits                           │
│     - Business hours                         │
│     ↓ ALL PASS                               │
│  3. ALLOW access                             │
└──────────────────────────────────────────────┘
```

### Policy Evaluation Example

**Scenario**: Alice wants to transfer $800

```
1. Authentication: ✅ Valid JWT token
2. RBAC Check: ✅ Has 'customer' role with 'transaction:create' permission
3. ABAC Checks:
   - Ownership: ✅ Alice owns the source account
   - Daily limit: ✅ $800 < $1000 limit (assuming $0 transferred today)
   - Business hours: ✅ Not a large transaction (< $5000)
   - Balance: ✅ Sufficient funds
4. Result: ✅ ALLOW
```

**Scenario**: Alice wants to transfer $1200

```
1. Authentication: ✅ Valid JWT token
2. RBAC Check: ✅ Has 'customer' role with 'transaction:create' permission
3. ABAC Checks:
   - Ownership: ✅ Alice owns the source account
   - Daily limit: ❌ $1200 > $1000 limit
4. Result: ❌ DENY (Policy: Daily limit exceeded)
```

## Real-World ABAC Scenarios

### Scenario 1: Time-based Access
```javascript
// Large withdrawals only during business hours
if (amount > 5000 && !isBusinessHours()) {
  deny('Large withdrawals only allowed 9 AM - 5 PM');
}
```

### Scenario 2: Geographic Restrictions
```javascript
// International transfers require verification
if (toAccount.country !== userCountry) {
  requireTwoFactorAuth();
}
```

### Scenario 3: Risk-based Decisions
```javascript
// Suspicious activity detection
if (transactionCount > 10 && timeWindow < '1 hour') {
  lockAccount('Unusual activity detected');
}
```

### Scenario 4: Hierarchical Access
```javascript
// Managers can approve transactions in their branch
if (user.role === 'manager' && 
    user.branch_id === transaction.branch_id &&
    transaction.amount < user.approval_limit) {
  allow();
}
```

## Testing Your Understanding

Before moving to Part 6, ensure you can:

1. ✅ Explain difference between RBAC and ABAC
2. ✅ Test ownership policies
3. ✅ Test daily transaction limits
4. ✅ Understand policy evaluation order
5. ✅ Combine RBAC and ABAC effectively
6. ✅ Create custom ABAC policies

## Discussion Questions

1. **RBAC vs ABAC Trade-offs**
   - When is RBAC sufficient?
   - When do you need ABAC?
   - Can they coexist?

2. **Policy Complexity**
   - How many policies are too many?
   - How to maintain complex policies?
   - Performance implications?

3. **Daily Limits**
   - Should limits reset at midnight?
   - Should weekends have different limits?
   - How to handle multiple currencies?

4. **Admin Bypass**
   - Should admins bypass ALL policies?
   - What about audit requirements?
   - How to prevent admin abuse?

## Next Steps

✅ You've completed Part 5!

You now have:
- Attribute-Based Access Control
- Policy-based authorization
- Daily transaction limits
- Context-aware access control
- Combined RBAC + ABAC

In **Part 6**, we'll add:
- Prometheus metrics collection
- Grafana visualization dashboards
- Alert on 3 failed login attempts
- Comprehensive audit logging
- Real-time monitoring

Continue to: [Part 6: Monitoring and Alerts](./6_monitoring_and_alerts.md)

## Additional Resources

- [NIST ABAC Guide](https://csrc.nist.gov/projects/attribute-based-access-control)
- [ABAC vs RBAC Comparison](https://www.okta.com/identity-101/role-based-access-control-vs-attribute-based-access-control/)
- [Policy-Based Access Control](https://en.wikipedia.org/wiki/Attribute-based_access_control)
- [XACML Standard](http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html)
