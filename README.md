# Simple Banking API - AAA Security Educational Guide

## Overview

This project is a **step-by-step educational guide** for building a REST API that demonstrates **AAA (Authentication, Authorization, and Accounting)** security concepts. The application is a simple banking system built with Express.js, MySQL, and Docker, featuring monitoring and alerting capabilities.

## Learning Objectives

By completing this guide, students will understand:

1. **Authentication** - Verifying user identity (username/password, Google OAuth, JWT)
2. **Authorization** - Controlling access to resources (RBAC, ABAC)
3. **Accounting** - Tracking and monitoring user activities (audit logs, metrics, alerts)

## Application Use Case: Simple Banking System

The banking application includes:
- **User Management** - Customers, managers, and administrators
- **Bank Accounts** - Create and manage accounts with balances
- **Transactions** - Deposits, withdrawals, and transfers
- **Security** - Role-based and attribute-based access control
- **Monitoring** - Track login attempts, account access, and failed authentication

## Technology Stack

- **Backend**: Node.js + Express.js
- **Database**: MySQL 8.0
- **Authentication**: JWT (JSON Web Tokens), Passport.js, bcrypt
- **OAuth**: Google OAuth 2.0
- **Database UI**: phpMyAdmin
- **Monitoring**: Prometheus
- **Visualization**: Grafana
- **Alerting**: Alertmanager
- **Container**: Docker + Docker Compose

## 6-Part Guide Structure

This guide is divided into **6 progressive parts**, where each part builds upon the previous one. Students can follow along and see the evolution of the codebase.

### [Part 1: Docker Compose Setup](./plan/1_docker_compose_setup.md)
**Goal**: Set up the development environment with Docker Compose

- Configure Docker services (Express, MySQL, phpMyAdmin)
- Create basic Express API structure
- Design MySQL database schema for banking system
- Implement health check endpoints
- Test database connectivity

**Deliverables**: Working Docker environment with API and database

---

### [Part 2: Username & Password Login with JWT](./plan/2_username_password_jwt.md)
**Goal**: Implement basic authentication system

- User registration with password hashing (bcrypt)
- Login endpoint with username/password
- JWT token generation (access + refresh tokens)
- JWT verification middleware
- Protected routes demonstration
- Login attempt tracking

**Security Concepts**: Authentication, Password Hashing, JWT

---

### [Part 3: Google OAuth Login with JWT](./plan/3_google_oauth_jwt.md)
**Goal**: Add OAuth 2.0 authentication provider

- Configure Google OAuth 2.0 credentials
- Implement Passport.js Google strategy
- OAuth callback handling
- Link Google accounts with local users
- Issue JWT after OAuth success
- Simple HTML login page

**Security Concepts**: OAuth 2.0, Third-party Authentication

---

### [Part 4: Role-Based Access Control (RBAC)](./plan/4_rbac_authorization.md)
**Goal**: Implement role-based authorization

- Define roles: Admin, Manager, Customer
- Define permissions: account:read, transaction:create, user:manage
- Create RBAC middleware
- Protect banking endpoints by role
- Role assignment by administrators
- Demonstrate permission hierarchy

**Security Concepts**: RBAC, Roles, Permissions

---

### [Part 5: Attribute-Based Access Control (ABAC)](./plan/5_abac_authorization.md)
**Goal**: Implement fine-grained attribute-based authorization

- User attributes (branch, account_type, limit)
- Resource attributes (account ownership, branch_id)
- ABAC policy rules
- Complex access scenarios:
  - Account owners can view their accounts
  - Branch managers can view accounts in their branch
  - Customers can only transfer within their daily limit
- ABAC middleware implementation

**Security Concepts**: ABAC, Policy-Based Authorization, Attribute Rules

---

### [Part 6: Monitoring and Alerts](./plan/6_monitoring_and_alerts.md)
**Goal**: Implement comprehensive monitoring and alerting

- Add Prometheus and Grafana to Docker Compose
- Instrument API with Prometheus metrics
- Track login attempts and failures
- Create audit logs for all actions
- Configure alert: 3 failed login attempts
- Build Grafana dashboard:
  - Failed login attempts chart
  - Active users gauge
  - API response times
  - Account lockout alerts
- Alertmanager integration

**Security Concepts**: Accounting, Audit Logging, Security Monitoring, Alerting

---

## How to Use This Guide

### For Students (Self-Learning)

**Estimated Time:** 14-20 hours total (2-4 hours per part)

1. **Follow sequentially** - Complete each part in order, don't skip ahead
2. **Hands-on learning** - Type the code yourself, don't copy-paste blindly
3. **Test everything** - Run all test commands before moving to next part
4. **Use the checklist** - Mark off items in [IMPLEMENTATION_CHECKLIST.md](./IMPLEMENTATION_CHECKLIST.md)
5. **Stuck? Check troubleshooting** - See [COMMON_ISSUES.md](./COMMON_ISSUES.md) before giving up
6. **Experiment** - Try breaking things to understand how they work
7. **Discussion questions** - Think through these on your own or discuss with peers

**Self-Assessment:** At the end of each part, you should be able to complete the "Testing Your Understanding" checklist successfully.

### For Students (Classroom)

1. **Follow along with instructor** - Complete each part as demonstrated
2. **Ask questions** - Discuss concepts with your instructor when unclear
3. **Participate in discussions** - Share your thoughts on discussion questions
4. **Test independently** - Run the test scenarios on your own machine
5. **Help peers** - If you finish early, help classmates who are stuck

### For Instructors

- Each part is **self-contained** with clear learning objectives
- Parts can be taught as **separate lessons** (1 per class session)
- **Code diffs** show what changes in each part
- **Test scenarios** help verify student understanding
- **Discussion questions** encourage critical thinking

## Project Structure (Final State)

```
api-app/
├── docker-compose.yml              # All services configuration
├── .env.example                    # Environment variables template
├── .gitignore
├── README.md
├── PLAN.md                         # This file
│
├── plan/                           # Tutorial guides
│   ├── 1_docker_compose_setup.md
│   ├── 2_username_password_jwt.md
│   ├── 3_google_oauth_jwt.md
│   ├── 4_rbac_authorization.md
│   ├── 5_abac_authorization.md
│   └── 6_monitoring_and_alerts.md
│
├── api/                            # Express.js application
│   ├── Dockerfile
│   ├── package.json
│   ├── .env
│   │
│   ├── src/
│   │   ├── server.js
│   │   ├── app.js
│   │   │
│   │   ├── config/              # Configuration files
│   │   │   ├── database.js
│   │   │   ├── passport.js
│   │   │   └── oauth.js
│   │   │
│   │   ├── middleware/          # Express middleware
│   │   │   ├── auth.js         # JWT verification
│   │   │   ├── rbac.js         # Role checks
│   │   │   ├── abac.js         # Attribute checks
│   │   │   ├── errorHandler.js
│   │   │   ├── rateLimiter.js
│   │   │   └── metrics.js      # Prometheus
│   │   │
│   │   ├── models/              # Database models
│   │   │   ├── User.js
│   │   │   ├── Role.js
│   │   │   ├── Permission.js
│   │   │   ├── Account.js
│   │   │   ├── Transaction.js
│   │   │   ├── LoginAttempt.js
│   │   │   └── AuditLog.js
│   │   │
│   │   ├── controllers/         # Business logic
│   │   │   ├── authController.js
│   │   │   ├── accountController.js
│   │   │   ├── transactionController.js
│   │   │   └── adminController.js
│   │   │
│   │   ├── routes/              # API routes
│   │   │   ├── index.js
│   │   │   ├── auth.js
│   │   │   ├── accounts.js
│   │   │   ├── transactions.js
│   │   │   └── admin.js
│   │   │
│   │   ├── services/            # Business services
│   │   │   ├── authService.js
│   │   │   ├── tokenService.js
│   │   │   ├── accountService.js
│   │   │   ├── auditService.js
│   │   │   └── alertService.js
│   │   │
│   │   ├── utils/               # Helper functions
│   │   │   ├── validators.js
│   │   │   ├── hashPassword.js
│   │   │   └── logger.js
│   │   │
│   │   └── db/
│   │       └── migrations/
│   │           └── init.sql    # Database schema
│   │
│   └── public/                  # Static files
│       └── login.html          # Simple login page
│
├── prometheus/
│   ├── prometheus.yml          # Prometheus config
│   └── alerts.yml              # Alert rules
│
└── grafana/
    └── provisioning/
        ├── datasources/
        │   └── prometheus.yml
        └── dashboards/
            ├── dashboard.yml
            └── banking-security.json
```

## API Endpoints (Final State)

### Public Endpoints
```
POST   /api/auth/register              # Create new user
POST   /api/auth/login                 # Login with username/password
GET    /api/auth/google                # Initiate Google OAuth
GET    /api/auth/google/callback       # OAuth callback
GET    /health                         # Health check
```

### Authenticated Endpoints (Requires JWT)
```
POST   /api/auth/logout                # Logout (revoke token)
POST   /api/auth/refresh               # Refresh JWT token
GET    /api/auth/me                    # Get current user info

# Accounts (Customer role)
GET    /api/accounts                   # List user's accounts
POST   /api/accounts                   # Create account
GET    /api/accounts/:id               # Get account details (ABAC)
PUT    /api/accounts/:id               # Update account
DELETE /api/accounts/:id               # Close account

# Transactions (Customer role)
GET    /api/transactions               # List user's transactions
POST   /api/transactions/deposit       # Deposit money
POST   /api/transactions/withdraw      # Withdraw money (ABAC)
POST   /api/transactions/transfer      # Transfer money (ABAC)

# Branch Management (Manager role)
GET    /api/accounts/branch/:id        # View branch accounts (ABAC)
GET    /api/transactions/branch/:id    # View branch transactions (ABAC)

# Administration (Admin role)
GET    /api/admin/users                # List all users
POST   /api/admin/users/:id/roles      # Assign roles
GET    /api/admin/audit-logs           # View audit logs
GET    /api/admin/login-attempts       # View login attempts
POST   /api/admin/users/:id/unlock     # Unlock account

# Monitoring
GET    /metrics                        # Prometheus metrics
```

## Security Features Demonstrated

### Authentication ✅
- [x] Username/password with bcrypt hashing
- [x] JWT access tokens (15-minute expiry)
- [x] JWT refresh tokens (7-day expiry)
- [x] Google OAuth 2.0 integration
- [x] Account lockout after 3 failed attempts

### Authorization ✅
- [x] RBAC with 3 roles: Admin, Manager, Customer
- [x] Permission-based access control
- [x] ABAC with user attributes (branch_id, account_type)
- [x] Resource ownership checks
- [x] Branch-based access control

### Accounting ✅
- [x] Audit logs for all API actions
- [x] Login attempt tracking
- [x] Prometheus metrics collection
- [x] Grafana visualization dashboards
- [x] Alerting on security events

## Prerequisites

### 🆕 New to Programming or Docker?
👉 **Start here:** [QUICKSTART.md - Beginner's Guide](./QUICKSTART.md)

### Required Software
- ✅ Docker & Docker Compose installed ([Install Guide](https://docs.docker.com/get-docker/))
- ✅ Node.js 18+ for local development ([Download](https://nodejs.org/))
- ✅ Text editor (VS Code recommended)
- ✅ Terminal/Command line access
- ✅ Google Cloud Console account (free tier) - needed for Part 3

### Required Knowledge (Minimum)
- **JavaScript basics** - Variables, functions, async/await
- **Command line basics** - Navigate directories, run commands
- **Basic understanding of:**
  - How web APIs work (requests/responses)
  - What databases do (store data in tables)
  - What Docker containers are (isolated environments)

### Recommended (But Not Required)
- Experience with Express.js
- SQL query basics
- REST API concepts
- Git version control

**Don't worry if you're not an expert!** The tutorial explains everything step-by-step.

## Quick Start

```bash
# Clone or navigate to project
cd api-app

# Copy environment variables
cp .env.example .env

# Edit .env with your Google OAuth credentials
nano .env

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f api

# Access services
# API: http://localhost:3000
# phpMyAdmin: http://localhost:8080
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3001 (admin/admin)
```

## Testing the Complete System

### 1. Register a User
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_customer",
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

### 2. Login and Get JWT
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_customer",
    "password": "SecurePass123!"
  }'
```

### 3. Create Bank Account (with JWT)
```bash
curl -X POST http://localhost:3000/api/accounts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "account_type": "savings",
    "initial_deposit": 1000.00
  }'
```

### 4. Test Failed Login Alert
```bash
# Try wrong password 3 times
for i in {1..3}; do
  curl -X POST http://localhost:3000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"john_customer","password":"wrong"}'
  sleep 1
done

# Check Grafana for alert
open http://localhost:3001
```

### 5. View Metrics
```bash
curl http://localhost:3000/metrics
```

## Learning Resources

### Recommended Reading
- [JWT Introduction](https://jwt.io/introduction)
- [OAuth 2.0 Simplified](https://aaronparecki.com/oauth-2-simplified/)
- [RBAC vs ABAC](https://www.okta.com/identity-101/role-based-access-control-vs-attribute-based-access-control/)
- [Prometheus Best Practices](https://prometheus.io/docs/practices/)

### Discussion Topics
1. Why use JWT instead of session cookies?
2. When should you use RBAC vs ABAC?
3. What are the security risks of password-based authentication?
4. How does OAuth 2.0 improve security?
5. Why is monitoring critical for security?

## Next Steps

After completing this guide, students can:
- Add email verification
- Implement two-factor authentication (2FA)
- Add rate limiting per user
- Implement password reset flow
- Add more complex ABAC policies
- Integrate with external banking APIs
- Deploy to production (Kubernetes, AWS, etc.)

## License

This educational project is provided for learning purposes.

## Support

For questions or issues, please contact your instructor or create an issue in the repository.

---

**Ready to start?** Begin with [Part 1: Docker Compose Setup](./plan/1_docker_compose_setup.md)
