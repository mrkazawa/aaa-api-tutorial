# Implementation Checklist

Use this checklist to ensure all steps are completed correctly in each part of the tutorial.

## Before Starting

- [ ] Docker and Docker Compose installed
- [ ] Node.js 18+ installed (for local development)
- [ ] Text editor (VS Code recommended)
- [ ] Terminal/command line access
- [ ] Google account (for OAuth in Part 3)

## Part 1: Docker Compose Setup

### Project Structure
- [ ] Created `api-app-tutorial/` directory
- [ ] Created `api/` subdirectory
- [ ] Created `api/src/` subdirectory
- [ ] Created all required subdirectories:
  - [ ] `api/src/config/`
  - [ ] `api/src/routes/`
  - [ ] `api/src/controllers/`
  - [ ] `api/src/db/migrations/`

### Configuration Files
- [ ] Created `docker-compose.yml` in root
- [ ] Created `.env.example` in root
- [ ] Created `.env` from `.env.example`
- [ ] Created `.gitignore` in root
- [ ] Created `api/Dockerfile`
- [ ] Created `api/.dockerignore`
- [ ] Created `api/package.json`

### Application Files
- [ ] Created `api/src/server.js`
- [ ] Created `api/src/app.js`
- [ ] Created `api/src/config/database.js`
- [ ] Created `api/src/routes/index.js`
- [ ] Created `api/src/controllers/healthController.js`
- [ ] Created `api/src/db/migrations/init.sql`

### Testing
- [ ] Ran `docker-compose up --build -d`
- [ ] All containers running: `docker-compose ps`
- [ ] Health check passes: `curl http://localhost:3000/health`
- [ ] phpMyAdmin accessible: http://localhost:8080
- [ ] Database tables created (verified in phpMyAdmin)
- [ ] Roles and permissions seeded
- [ ] Sample branches created

## Part 2: Username & Password Login with JWT

### New Directories
- [ ] Created `api/src/utils/`
- [ ] Created `api/src/services/`
- [ ] Created `api/src/middleware/`

### Dependencies
- [ ] Updated `api/package.json` with new dependencies
- [ ] Rebuilt containers: `docker-compose down && docker-compose up --build -d`
- [ ] Verified dependencies installed (check logs)

### Utility Files
- [ ] Created `api/src/utils/hashPassword.js`
- [ ] Created `api/src/utils/validators.js`

### Service Files
- [ ] Created `api/src/services/tokenService.js`
- [ ] Created `api/src/services/authService.js`

### Controller Files
- [ ] Created `api/src/controllers/authController.js`

### Middleware Files
- [ ] Created `api/src/middleware/auth.js`

### Route Files
- [ ] Created `api/src/routes/auth.js`
- [ ] Updated `api/src/routes/index.js` to include auth routes

### Testing
- [ ] API restarted successfully
- [ ] Registered test user: `alice_customer`
- [ ] Login successful with correct password
- [ ] Login fails with wrong password
- [ ] JWT token received on successful login
- [ ] Protected route `/api/auth/me` works with valid token
- [ ] Protected route fails without token (401)
- [ ] Account lockout triggers after 3 failed attempts
- [ ] Login attempts logged in database
- [ ] Lockout records created in database

## Part 3: Google OAuth Login with JWT

### Prerequisites
- [ ] Google Cloud Console account created
- [ ] Google Cloud project created
- [ ] OAuth consent screen configured
- [ ] OAuth 2.0 Client ID created
- [ ] Redirect URI configured: `http://localhost:3000/api/auth/google/callback`
- [ ] Client ID and Secret copied

### New Directories
- [ ] Created `api/public/` directory

### Configuration
- [ ] Updated `.env` with Google OAuth credentials
- [ ] Updated `api/package.json` with Passport dependencies
- [ ] Rebuilt containers

### Files
- [ ] Created `api/src/config/passport.js`
- [ ] Updated `api/src/services/authService.js` with OAuth functions
- [ ] Updated `api/src/controllers/authController.js` with OAuth handlers
- [ ] Updated `api/src/routes/auth.js` with OAuth routes
- [ ] Updated `api/src/app.js` to initialize Passport
- [ ] Created `api/public/login.html`

### Testing
- [ ] Login page accessible: http://localhost:3000/login.html
- [ ] "Continue with Google" button works
- [ ] Google OAuth consent screen appears
- [ ] After approval, redirected back to app
- [ ] JWT tokens received after OAuth
- [ ] New user created in database
- [ ] User with existing email linked correctly
- [ ] Login via username/password still works
- [ ] Login via Google works on repeat

## Part 4: RBAC Authorization

### New Directories
- [ ] Created `api/src/models/` directory

### Middleware Files
- [ ] Created `api/src/middleware/rbac.js`

### Model Files
- [ ] Created `api/src/models/Account.js`
- [ ] Created `api/src/models/Transaction.js`

### Controller Files
- [ ] Created `api/src/controllers/accountController.js`
- [ ] Created `api/src/controllers/transactionController.js`
- [ ] Created `api/src/controllers/adminController.js`

### Route Files
- [ ] Created `api/src/routes/accounts.js`
- [ ] Created `api/src/routes/transactions.js`
- [ ] Created `api/src/routes/admin.js`
- [ ] Updated `api/src/routes/index.js` with new routes

### Database Setup
- [ ] Assigned roles to test users in database
- [ ] Verified role assignments with SQL query

### Testing
- [ ] Customer can create own account
- [ ] Customer can view own accounts
- [ ] Customer cannot view other user's accounts (403)
- [ ] Customer cannot access admin endpoints (403)
- [ ] Manager can view branch accounts
- [ ] Manager cannot access admin endpoints (403)
- [ ] Admin can view all users
- [ ] Admin can view all accounts
- [ ] Admin can assign roles
- [ ] Admin can view login attempts
- [ ] RBAC middleware logs access attempts

## Part 5: ABAC Authorization

### Service Files
- [ ] Created `api/src/services/abacService.js`

### Middleware Files
- [ ] Created `api/src/middleware/abac.js`

### Database Setup
- [ ] Added user attributes to test users
- [ ] Verified attributes in database

### Updated Files
- [ ] Updated `api/src/controllers/transactionController.js` with ABAC
- [ ] Updated `api/src/routes/accounts.js` with ABAC middleware
- [ ] Updated `api/src/routes/transactions.js` with ABAC middleware

### Testing
- [ ] Customer can access own account
- [ ] Customer cannot access other's account (ABAC deny)
- [ ] Manager can access branch accounts (ABAC allow)
- [ ] Transfer under daily limit succeeds
- [ ] Transfer exceeding daily limit fails with proper message
- [ ] Large transaction outside business hours fails
- [ ] Admin bypasses all ABAC limits
- [ ] Today's transfer total calculated correctly

## Part 6: Monitoring and Alerts

### New Directories
- [ ] Created `prometheus/` directory
- [ ] Created `grafana/provisioning/datasources/` directory
- [ ] Created `grafana/provisioning/dashboards/` directory

### Configuration Files
- [ ] Created `prometheus/prometheus.yml`
- [ ] Created `prometheus/alerts.yml`
- [ ] Created `prometheus/alertmanager.yml`
- [ ] Created `grafana/provisioning/datasources/prometheus.yml`
- [ ] Created `grafana/provisioning/dashboards/dashboard.yml`

### Updated Files
- [ ] Updated `docker-compose.yml` with monitoring services
- [ ] Updated `api/package.json` with monitoring dependencies
- [ ] Created `api/src/middleware/metrics.js`
- [ ] Created `api/src/services/auditService.js`
- [ ] Updated `api/src/app.js` with metrics and audit logging
- [ ] Updated `api/src/controllers/authController.js` with metric tracking

### Testing Services
- [ ] All containers started successfully
- [ ] Prometheus accessible: http://localhost:9090
- [ ] Grafana accessible: http://localhost:3001
- [ ] Alertmanager accessible: http://localhost:9093
- [ ] API metrics endpoint works: `curl http://localhost:3000/metrics`

### Testing Metrics
- [ ] Metrics visible in Prometheus
- [ ] Can query `login_attempts_total`
- [ ] Can query `http_requests_total`
- [ ] Can query `active_accounts_total`
- [ ] Database metrics updating every 30 seconds

### Testing Grafana
- [ ] Logged into Grafana (admin/admin)
- [ ] Prometheus datasource configured
- [ ] Created first dashboard panel
- [ ] Added "Failed Login Attempts" panel
- [ ] Added "Active Sessions" panel
- [ ] Added "HTTP Request Rate" panel
- [ ] Dashboard updates in real-time

### Testing Alerts
- [ ] Triggered 3 failed login attempts
- [ ] Alert visible in Prometheus: http://localhost:9090/alerts
- [ ] Alert shows "FIRING" status
- [ ] Alert visible in Alertmanager
- [ ] Waited for alert to resolve
- [ ] Alert shows "resolved" after successful login

### Testing Audit Logs
- [ ] Audit logs being written to database
- [ ] Can query recent audit logs
- [ ] Audit logs contain user_id, action, resource
- [ ] Sensitive data (password) not logged
- [ ] Logs correlate with API requests

## Final Integration Testing

### Complete User Flow
- [ ] Register new user via API
- [ ] Login with username/password
- [ ] Create bank account
- [ ] Deposit money
- [ ] Transfer money (within limit)
- [ ] Try transfer exceeding limit (should fail)
- [ ] View transaction history
- [ ] Logout
- [ ] Login with Google OAuth
- [ ] Access previously created accounts

### Admin Operations
- [ ] Login as admin
- [ ] View all users
- [ ] Assign role to user
- [ ] View all accounts
- [ ] View all transactions
- [ ] View login attempts
- [ ] Unlock locked account
- [ ] View audit logs

### Monitoring Validation
- [ ] All metrics updating
- [ ] All dashboard panels showing data
- [ ] No errors in Prometheus logs
- [ ] No errors in Grafana logs
- [ ] Alerts configured and tested
- [ ] Audit logs complete and accurate

## Documentation Review

- [ ] README.md is up to date
- [ ] All 6 tutorial parts are complete
- [ ] COMMON_ISSUES.md reviewed
- [ ] All code examples tested
- [ ] All curl commands work
- [ ] All SQL queries work
- [ ] Screenshots/diagrams accurate

## Production Readiness (Optional)

- [ ] HTTPS enabled
- [ ] Environment variables secured
- [ ] Database backups configured
- [ ] Rate limiting implemented
- [ ] CORS properly configured
- [ ] Logs shipped to external service
- [ ] Secrets in secret manager
- [ ] CI/CD pipeline set up
- [ ] Deployment documented

---

## Notes

Use this space to note any issues or customizations:

```
[Your notes here]
```

---

**Completion Date:** __________________

**Completed By:** __________________

**Instructor/Reviewer:** __________________
