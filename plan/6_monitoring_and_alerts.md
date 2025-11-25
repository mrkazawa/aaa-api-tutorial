# Part 6: Monitoring and Alerts

## Learning Objectives

By the end of this part, you will:
- ✅ Understand the third "A" in AAA: **Accounting**
- ✅ Implement Prometheus metrics collection
- ✅ Create Grafana visualization dashboards
- ✅ Set up alerts for security events (3 failed logins)
- ✅ Implement comprehensive audit logging
- ✅ Monitor system health and performance

## Overview

In Part 6, we'll implement **Accounting** - the final "A" in AAA security. Accounting tracks user activities, system events, and security incidents. We'll use:
- **Prometheus** - Metrics collection and storage
- **Grafana** - Visualization and alerting
- **Alertmanager** - Alert notification handling

## Accounting Concepts

### What is Accounting in AAA?

**Accounting** tracks:
1. **Who** performed an action (user identification)
2. **What** action was performed (operation)
3. **When** it happened (timestamp)
4. **Where** it came from (IP address, location)
5. **Result** (success/failure)

### Why Accounting Matters

- **Security Monitoring** - Detect suspicious activities
- **Compliance** - Meet regulatory requirements
- **Auditing** - Track all system changes
- **Troubleshooting** - Debug issues
- **Analytics** - Understand usage patterns

## Architecture

```
┌─────────────────────────────────────────────────┐
│              Banking API                         │
│  ┌──────────────────────────────────────────┐  │
│  │  Request Handler                         │  │
│  │   ↓                                      │  │
│  │  Metrics Middleware ──▶ Prometheus       │  │
│  │   ↓                     Counters         │  │
│  │  Auth/Transaction       Gauges           │  │
│  │   ↓                     Histograms       │  │
│  │  Audit Logger ──▶ audit_logs table       │  │
│  └──────────────────────────────────────────┘  │
└─────────────┬───────────────────────────────────┘
              │
              ▼
    ┌─────────────────┐
    │   Prometheus    │  Scrapes /metrics endpoint
    │   - Stores data │  Evaluates alert rules
    │   - Triggers alerts
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐         ┌──────────────┐
    │    Grafana      │────────▶│ Alertmanager │
    │  - Dashboards   │         │ - Email      │
    │  - Visualizations         │ - Slack      │
    └─────────────────┘         └──────────────┘
```

## Step 1: Update Docker Compose

Update `docker-compose.yml` to add Prometheus, Grafana, and Alertmanager:

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
      - GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
      - GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}
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

  # Prometheus - Metrics Collection
  prometheus:
    image: prom/prometheus:latest
    container_name: banking-prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - ./prometheus/alerts.yml:/etc/prometheus/alerts.yml
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--web.enable-lifecycle'
    networks:
      - banking-network
    restart: unless-stopped
    depends_on:
      - api

  # Grafana - Visualization
  grafana:
    image: grafana/grafana:latest
    container_name: banking-grafana
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_SERVER_ROOT_URL=http://localhost:3001
    volumes:
      - ./grafana/provisioning:/etc/grafana/provisioning
      - grafana-data:/var/lib/grafana
    networks:
      - banking-network
    restart: unless-stopped
    depends_on:
      - prometheus

  # Alertmanager - Alert Routing
  alertmanager:
    image: prom/alertmanager:latest
    container_name: banking-alertmanager
    ports:
      - "9093:9093"
    volumes:
      - ./prometheus/alertmanager.yml:/etc/alertmanager/alertmanager.yml
      - alertmanager-data:/alertmanager
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
    networks:
      - banking-network
    restart: unless-stopped

volumes:
  mysql-data:
    driver: local
  prometheus-data:
    driver: local
  grafana-data:
    driver: local
  alertmanager-data:
    driver: local

networks:
  banking-network:
    driver: bridge
```

## Step 2: Configure Prometheus

Create Prometheus configuration files:

### `prometheus/prometheus.yml`

```yaml
# Prometheus Configuration
global:
  scrape_interval: 15s      # Scrape targets every 15 seconds
  evaluation_interval: 15s   # Evaluate rules every 15 seconds
  external_labels:
    cluster: 'banking-api'
    environment: 'development'

# Alertmanager configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']

# Load alert rules
rule_files:
  - 'alerts.yml'

# Scrape configurations
scrape_configs:
  # Banking API metrics
  - job_name: 'banking-api'
    static_configs:
      - targets: ['api:3000']
    metrics_path: '/metrics'
    scrape_interval: 10s
    scrape_timeout: 5s

  # Prometheus self-monitoring
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
```

### `prometheus/alerts.yml`

```yaml
# Alert Rules for Banking API
groups:
  - name: security_alerts
    interval: 30s
    rules:
      # Alert on 3 failed login attempts within 5 minutes
      - alert: MultipleFailedLogins
        expr: |
          sum(increase(login_attempts_failed_total[5m])) by (username) >= 3
        for: 1m
        labels:
          severity: warning
          category: security
        annotations:
          summary: "Multiple failed login attempts detected"
          description: "User {{ $labels.username }} has {{ $value }} failed login attempts in the last 5 minutes"
          action: "Account may be locked automatically"

      # Alert on account lockout
      - alert: AccountLocked
        expr: |
          increase(account_lockouts_total[5m]) > 0
        for: 30s
        labels:
          severity: warning
          category: security
        annotations:
          summary: "Account locked due to failed login attempts"
          description: "{{ $value }} account(s) have been locked in the last 5 minutes"
          action: "Review login attempts and unlock if legitimate"

      # Alert on high unauthorized access attempts
      - alert: UnauthorizedAccessAttempts
        expr: |
          rate(http_requests_total{status="403"}[5m]) * 300 > 10
        for: 2m
        labels:
          severity: warning
          category: security
        annotations:
          summary: "High rate of unauthorized access attempts"
          description: "{{ $value }} unauthorized requests (403) in the last 5 minutes"
          action: "Investigate potential attack"

      # Alert on high authentication failures
      - alert: HighAuthenticationFailureRate
        expr: |
          rate(http_requests_total{status="401"}[5m]) * 300 > 20
        for: 2m
        labels:
          severity: warning
          category: security
        annotations:
          summary: "High authentication failure rate"
          description: "{{ $value }} authentication failures in the last 5 minutes"

  - name: performance_alerts
    interval: 30s
    rules:
      # Alert on high API error rate
      - alert: HighErrorRate
        expr: |
          rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 2m
        labels:
          severity: critical
          category: performance
        annotations:
          summary: "High API error rate detected"
          description: "API error rate is {{ $value }} requests/second"
          action: "Check API logs and database connectivity"

      # Alert on slow API response time
      - alert: SlowAPIResponse
        expr: |
          histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 2
        for: 5m
        labels:
          severity: warning
          category: performance
        annotations:
          summary: "API response time is slow"
          description: "95th percentile response time is {{ $value }}s"
          action: "Investigate database queries and server load"

      # Alert on high API request rate
      - alert: HighRequestRate
        expr: |
          rate(http_requests_total[1m]) > 100
        for: 5m
        labels:
          severity: info
          category: performance
        annotations:
          summary: "High API request rate"
          description: "Receiving {{ $value }} requests per second"

  - name: business_alerts
    interval: 60s
    rules:
      # Alert on large transactions (over $10,000)
      - alert: LargeTransaction
        expr: |
          increase(transactions_large_total[10m]) > 0
        for: 1m
        labels:
          severity: info
          category: business
        annotations:
          summary: "Large transaction detected"
          description: "{{ $value }} transaction(s) over $10,000 in the last 10 minutes"
          action: "Review for potential fraud"

      # Alert on unusual transaction volume
      - alert: UnusualTransactionVolume
        expr: |
          rate(transactions_total[5m]) > 10
        for: 10m
        labels:
          severity: warning
          category: business
        annotations:
          summary: "Unusual transaction volume"
          description: "Transaction rate is {{ $value }} per second"
```

### `prometheus/alertmanager.yml`

```yaml
# Alertmanager Configuration
global:
  resolve_timeout: 5m

# Alert routing
route:
  receiver: 'default'
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  
  routes:
    # Security alerts - high priority
    - match:
        category: security
      receiver: 'security-team'
      group_wait: 5s
      repeat_interval: 3h
    
    # Performance alerts
    - match:
        category: performance
      receiver: 'ops-team'
      repeat_interval: 6h
    
    # Business alerts
    - match:
        category: business
      receiver: 'fraud-team'
      repeat_interval: 24h

# Receivers (notification channels)
receivers:
  - name: 'default'
    webhook_configs:
      - url: 'http://api:3000/api/webhooks/alerts'
        send_resolved: true

  - name: 'security-team'
    webhook_configs:
      - url: 'http://api:3000/api/webhooks/security-alerts'
        send_resolved: true
    # Email configuration (optional - requires SMTP setup)
    # email_configs:
    #   - to: 'security@example.com'
    #     from: 'alertmanager@example.com'
    #     smarthost: 'smtp.gmail.com:587'
    #     auth_username: 'your-email@gmail.com'
    #     auth_password: 'your-app-password'

  - name: 'ops-team'
    webhook_configs:
      - url: 'http://api:3000/api/webhooks/ops-alerts'

  - name: 'fraud-team'
    webhook_configs:
      - url: 'http://api:3000/api/webhooks/fraud-alerts'

# Inhibition rules (suppress certain alerts when others are firing)
inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'cluster']
```

## Step 3: Configure Grafana Datasources

### `grafana/provisioning/datasources/prometheus.yml`

```yaml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
    jsonData:
      timeInterval: "15s"
```

### `grafana/provisioning/dashboards/dashboard.yml`

```yaml
apiVersion: 1

providers:
  - name: 'Banking API Dashboards'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards
```

## Step 4: Install Prometheus Client

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
    "express-session": "^1.17.3",
    "prom-client": "^15.1.0",
    "winston": "^3.11.0"
  }
}
```

## Step 5: Create Metrics Middleware

### `api/src/middleware/metrics.js`

```javascript
const client = require('prom-client');

// Create a Registry
const register = new client.Registry();

// Add default metrics (CPU, memory, etc.)
client.collectDefaultMetrics({ 
  register,
  prefix: 'banking_api_'
});

// ===================================
// HTTP METRICS
// ===================================

// HTTP request duration histogram
const httpRequestDuration = new client.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status'],
  buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10],
  registers: [register]
});

// HTTP request total counter
const httpRequestTotal = new client.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status'],
  registers: [register]
});

// ===================================
// AUTHENTICATION METRICS
// ===================================

// Login attempts counter
const loginAttemptsTotal = new client.Counter({
  name: 'login_attempts_total',
  help: 'Total login attempts',
  labelNames: ['username', 'success', 'method'],
  registers: [register]
});

// Failed login attempts
const loginAttemptsFailed = new client.Counter({
  name: 'login_attempts_failed_total',
  help: 'Total failed login attempts',
  labelNames: ['username', 'reason'],
  registers: [register]
});

// Account lockouts counter
const accountLockoutsTotal = new client.Counter({
  name: 'account_lockouts_total',
  help: 'Total account lockouts',
  labelNames: ['username'],
  registers: [register]
});

// Active sessions gauge
const activeSessionsGauge = new client.Gauge({
  name: 'active_sessions_total',
  help: 'Number of currently active sessions',
  registers: [register]
});

// ===================================
// BANKING METRICS
// ===================================

// Accounts created counter
const accountsCreatedTotal = new client.Counter({
  name: 'accounts_created_total',
  help: 'Total bank accounts created',
  labelNames: ['account_type', 'branch_id'],
  registers: [register]
});

// Active accounts gauge
const activeAccountsGauge = new client.Gauge({
  name: 'active_accounts_total',
  help: 'Number of active bank accounts',
  labelNames: ['account_type'],
  registers: [register]
});

// Transactions counter
const transactionsTotal = new client.Counter({
  name: 'transactions_total',
  help: 'Total transactions',
  labelNames: ['type', 'status'],
  registers: [register]
});

// Transaction amount histogram
const transactionAmount = new client.Histogram({
  name: 'transaction_amount_dollars',
  help: 'Transaction amounts in dollars',
  labelNames: ['type'],
  buckets: [10, 50, 100, 500, 1000, 5000, 10000, 50000],
  registers: [register]
});

// Large transactions counter (over $10,000)
const largeTransactionsTotal = new client.Counter({
  name: 'transactions_large_total',
  help: 'Transactions over $10,000',
  labelNames: ['type'],
  registers: [register]
});

// Total account balance gauge
const totalBalanceGauge = new client.Gauge({
  name: 'total_account_balance_dollars',
  help: 'Total balance across all accounts',
  registers: [register]
});

// ===================================
// AUTHORIZATION METRICS
// ===================================

// Authorization denials counter
const authorizationDenied = new client.Counter({
  name: 'authorization_denied_total',
  help: 'Total authorization denials',
  labelNames: ['reason', 'resource'],
  registers: [register]
});

// RBAC checks counter
const rbacChecksTotal = new client.Counter({
  name: 'rbac_checks_total',
  help: 'Total RBAC permission checks',
  labelNames: ['role', 'permission', 'result'],
  registers: [register]
});

// ABAC policy evaluations counter
const abacEvaluationsTotal = new client.Counter({
  name: 'abac_evaluations_total',
  help: 'Total ABAC policy evaluations',
  labelNames: ['policy', 'result'],
  registers: [register]
});

// ===================================
// MIDDLEWARE
// ===================================

/**
 * Middleware to track HTTP requests
 */
const metricsMiddleware = (req, res, next) => {
  const start = Date.now();
  
  // Track request completion
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    const route = req.route ? req.route.path : req.path;
    const status = res.statusCode;
    
    // Record metrics
    httpRequestDuration.labels(req.method, route, status).observe(duration);
    httpRequestTotal.labels(req.method, route, status).inc();
  });
  
  next();
};

// ===================================
// HELPER FUNCTIONS
// ===================================

/**
 * Update database-derived metrics
 * Should be called periodically
 */
const updateDatabaseMetrics = async (db) => {
  try {
    // Active accounts by type
    const [accountCounts] = await db.query(
      `SELECT account_type, COUNT(*) as count 
       FROM accounts 
       WHERE status = 'active' 
       GROUP BY account_type`
    );
    
    // Reset and set gauges
    activeAccountsGauge.reset();
    accountCounts.forEach(row => {
      activeAccountsGauge.labels(row.account_type).set(row.count);
    });
    
    // Total balance
    const [balanceResult] = await db.query(
      'SELECT COALESCE(SUM(balance), 0) as total FROM accounts WHERE status = "active"'
    );
    totalBalanceGauge.set(parseFloat(balanceResult[0].total));
    
    // Active sessions (from refresh_tokens)
    const [sessionCount] = await db.query(
      'SELECT COUNT(*) as count FROM refresh_tokens WHERE expires_at > NOW() AND revoked = FALSE'
    );
    activeSessionsGauge.set(sessionCount[0].count);
    
  } catch (error) {
    console.error('Error updating database metrics:', error);
  }
};

// Export everything
module.exports = {
  register,
  metricsMiddleware,
  
  // Metrics
  httpRequestDuration,
  httpRequestTotal,
  loginAttemptsTotal,
  loginAttemptsFailed,
  accountLockoutsTotal,
  activeSessionsGauge,
  accountsCreatedTotal,
  activeAccountsGauge,
  transactionsTotal,
  transactionAmount,
  largeTransactionsTotal,
  totalBalanceGauge,
  authorizationDenied,
  rbacChecksTotal,
  abacEvaluationsTotal,
  
  // Helper
  updateDatabaseMetrics
};
```

## Step 6: Create Audit Logger

### `api/src/services/auditService.js`

```javascript
const db = require('../config/database');

/**
 * Log an audit event
 * @param {Object} auditData - Audit log data
 */
exports.log = async (auditData) => {
  const {
    userId,
    action,
    resourceType,
    resourceId,
    ipAddress,
    userAgent,
    requestMethod,
    requestPath,
    statusCode,
    details
  } = auditData;
  
  try {
    await db.query(
      `INSERT INTO audit_logs 
       (user_id, action, resource_type, resource_id, ip_address, user_agent, 
        request_method, request_path, status_code, details)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        userId || null,
        action,
        resourceType || null,
        resourceId || null,
        ipAddress || null,
        userAgent || null,
        requestMethod || null,
        requestPath || null,
        statusCode || null,
        details ? JSON.stringify(details) : null
      ]
    );
  } catch (error) {
    console.error('Audit log error:', error);
    // Don't throw - audit logging should not break the application
  }
};

/**
 * Create audit middleware
 */
exports.auditMiddleware = (req, res, next) => {
  // Capture response
  const originalSend = res.send;
  
  res.send = function(data) {
    // Log after response is sent
    setImmediate(() => {
      exports.log({
        userId: req.user?.id,
        action: `${req.method} ${req.path}`,
        resourceType: extractResourceType(req.path),
        resourceId: extractResourceId(req.path, req.params),
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('user-agent'),
        requestMethod: req.method,
        requestPath: req.path,
        statusCode: res.statusCode,
        details: {
          query: req.query,
          body: sanitizeBody(req.body)
        }
      });
    });
    
    originalSend.call(this, data);
  };
  
  next();
};

/**
 * Extract resource type from path
 */
function extractResourceType(path) {
  const match = path.match(/\/api\/([^\/]+)/);
  return match ? match[1] : null;
}

/**
 * Extract resource ID from path
 */
function extractResourceId(path, params) {
  return params.id || params.accountId || params.transactionId || null;
}

/**
 * Sanitize request body (remove sensitive data)
 */
function sanitizeBody(body) {
  if (!body) return null;
  
  const sanitized = { ...body };
  
  // Remove sensitive fields
  delete sanitized.password;
  delete sanitized.token;
  delete sanitized.refreshToken;
  delete sanitized.accessToken;
  
  return sanitized;
}

/**
 * Get recent audit logs
 */
exports.getRecentLogs = async (limit = 100, filters = {}) => {
  let query = 'SELECT * FROM audit_logs WHERE 1=1';
  const params = [];
  
  if (filters.userId) {
    query += ' AND user_id = ?';
    params.push(filters.userId);
  }
  
  if (filters.action) {
    query += ' AND action LIKE ?';
    params.push(`%${filters.action}%`);
  }
  
  if (filters.resourceType) {
    query += ' AND resource_type = ?';
    params.push(filters.resourceType);
  }
  
  query += ' ORDER BY created_at DESC LIMIT ?';
  params.push(limit);
  
  const [rows] = await db.query(query, params);
  return rows;
};
```

## Step 7: Integrate Metrics into Application

Update `api/src/app.js` to use metrics and audit logging:

```javascript
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const passport = require('./config/passport');
const routes = require('./routes');
const { metricsMiddleware, updateDatabaseMetrics, register } = require('./middleware/metrics');
const { auditMiddleware } = require('./services/auditService');
const db = require('./config/database');

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false
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

// Metrics middleware (should be early)
app.use(metricsMiddleware);

// Audit logging middleware
app.use(auditMiddleware);

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Serve static files
app.use(express.static('public'));

// API routes
app.use('/api', routes);

// Metrics endpoint for Prometheus
app.get('/metrics', async (req, res) => {
  try {
    // Update database metrics before serving
    await updateDatabaseMetrics(db);
    
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch (error) {
    res.status(500).end(error);
  }
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: '🏦 Welcome to Banking API',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      metrics: '/metrics',
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

// Update database metrics every 30 seconds
setInterval(() => {
  updateDatabaseMetrics(db).catch(console.error);
}, 30000);

module.exports = app;
```

## Step 8: Update Controllers to Track Metrics

Update `api/src/controllers/authController.js` to track metrics:

```javascript
// Add at top
const { 
  loginAttemptsTotal, 
  loginAttemptsFailed, 
  accountLockoutsTotal 
} = require('../middleware/metrics');

// Update login function
exports.login = async (req, res) => {
  try {
    const { username, password } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('user-agent') || 'unknown';
    
    // Check if account is locked
    const isLocked = await authService.isAccountLocked(username);
    if (isLocked) {
      await authService.logLoginAttempt(username, ipAddress, userAgent, false, 'account_locked');
      
      // Track metrics
      loginAttemptsTotal.labels(username, 'false', 'password').inc();
      loginAttemptsFailed.labels(username, 'account_locked').inc();
      
      return res.status(423).json({
        error: 'Account is locked due to multiple failed login attempts',
        message: `Please try again in ${process.env.ACCOUNT_LOCKOUT_DURATION_MINUTES || 15} minutes`
      });
    }
    
    // Verify credentials
    const user = await authService.verifyCredentials(username, password);
    
    if (!user) {
      // Log failed attempt
      await authService.logLoginAttempt(username, ipAddress, userAgent, false, 'invalid_credentials');
      
      // Track metrics
      loginAttemptsTotal.labels(username, 'false', 'password').inc();
      loginAttemptsFailed.labels(username, 'invalid_credentials').inc();
      
      // Check if should lock account
      const failedAttempts = await authService.getRecentFailedAttempts(username, 15);
      
      if (failedAttempts >= parseInt(process.env.MAX_LOGIN_ATTEMPTS || 3)) {
        const tempUser = await authService.findUserByUsername(username);
        if (tempUser) {
          await authService.lockAccount(tempUser.id);
          accountLockoutsTotal.labels(username).inc();
          
          console.log(`🔒 Account locked: ${username} (${failedAttempts} failed attempts)`);
          
          return res.status(423).json({
            error: 'Account locked due to multiple failed login attempts',
            message: `Your account has been locked for ${process.env.ACCOUNT_LOCKOUT_DURATION_MINUTES || 15} minutes`
          });
        }
      }
      
      return res.status(401).json({
        error: 'Invalid username or password',
        attemptsRemaining: Math.max(0, parseInt(process.env.MAX_LOGIN_ATTEMPTS || 3) - failedAttempts)
      });
    }
    
    // Success
    await authService.logLoginAttempt(username, ipAddress, userAgent, true);
    await authService.updateLastLogin(user.id);
    
    // Track metrics
    loginAttemptsTotal.labels(username, 'true', 'password').inc();
    
    // Generate tokens
    const accessToken = tokenService.generateAccessToken(user);
    const refreshToken = await tokenService.generateRefreshToken(user.id);
    
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
```

Similarly, update account and transaction controllers to track metrics when accounts are created and transactions are performed.

## Step 9: Create Grafana Dashboard

Create `grafana/provisioning/dashboards/banking-security.json`:

**Note:** The complete dashboard JSON is quite large. Below is a simplified structure. After starting Grafana, you can:
1. Create your dashboard visually in the Grafana UI (http://localhost:3001)
2. Export it as JSON
3. Save it to `grafana/provisioning/dashboards/banking-security.json`

Simplified dashboard structure:

```json
{
  "dashboard": {
    "title": "Banking API - Security Monitoring",
    "panels": [
      {
        "title": "Failed Login Attempts (Last Hour)",
        "targets": [{
          "expr": "increase(login_attempts_failed_total[1h])"
        }]
      },
      {
        "title": "Account Lockouts",
        "targets": [{
          "expr": "account_lockouts_total"
        }]
      },
      {
        "title": "Active Sessions",
        "targets": [{
          "expr": "active_sessions_total"
        }]
      },
      {
        "title": "HTTP Request Rate",
        "targets": [{
          "expr": "rate(http_requests_total[5m])"
        }]
      },
      {
        "title": "API Response Time (p95)",
        "targets": [{
          "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))"
        }]
      },
      {
        "title": "Total Account Balance",
        "targets": [{
          "expr": "total_account_balance_dollars"
        }]
      },
      {
        "title": "Transaction Volume",
        "targets": [{
          "expr": "rate(transactions_total[5m]) * 60"
        }]
      },
      {
        "title": "Authorization Denials",
        "targets": [{
          "expr": "increase(authorization_denied_total[1h])"
        }]
      }
    ]
  }
}
```

## Step 10: Start and Test Monitoring

### 1. Create Required Directories

```bash
# Create directories for Prometheus and Grafana configuration
mkdir -p prometheus
mkdir -p grafana/provisioning/datasources
mkdir -p grafana/provisioning/dashboards
```

### 2. Start All Services

```bash
# Create necessary directories
mkdir -p prometheus grafana/provisioning/datasources grafana/provisioning/dashboards

# Start services
docker-compose up -d

# Check logs
docker-compose logs -f
```

### 2. Access Monitoring Tools

- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3001 (admin/admin)
- **Alertmanager**: http://localhost:9093

### 3. Test Metrics Collection

```bash
# View metrics
curl http://localhost:3000/metrics

# You should see metrics like:
# login_attempts_total{username="alice",success="true"} 1
# http_requests_total{method="POST",route="/api/auth/login",status="200"} 1
# active_accounts_total{account_type="savings"} 5
```

### 4. Trigger Failed Login Alert

```bash
# Attempt failed logins 3 times
for i in {1..3}; do
  curl -X POST http://localhost:3000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"alice_customer","password":"WrongPassword"}'
  sleep 1
done

# Check Prometheus alerts: http://localhost:9090/alerts
# Check Alertmanager: http://localhost:9093
```

### 5. View Grafana Dashboard

1. Open http://localhost:3001
2. Login: admin / admin
3. Skip password change (or set new password)
4. Go to "Dashboards" (left sidebar, four squares icon)

**Create your first dashboard:**

1. Click "+ Create" → "Dashboard"
2. Click "Add visualization"
3. Select "Prometheus" as data source
4. In the query editor, enter: `increase(login_attempts_failed_total[1h])`
5. Change visualization type to "Time series"
6. Set panel title: "Failed Login Attempts (Last Hour)"
7. Click "Apply"
8. Click "Save dashboard" (disk icon in top right)
9. Name it "Banking API - Security Monitoring"

**Add more panels following the same process:**
- Panel 2: `account_lockouts_total` (Stat)
- Panel 3: `active_sessions_total` (Gauge)
- Panel 4: `rate(http_requests_total[5m])` (Graph)
- Panel 5: `histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))` (Graph)

### 6. View Audit Logs

```bash
docker exec -it banking-mysql mysql -u root -p
# Password: rootpass123

USE banking_db;

-- View recent audit logs
SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 20;

-- View login attempts
SELECT username, success, failure_reason, attempted_at 
FROM login_attempts 
ORDER BY attempted_at DESC 
LIMIT 20;

EXIT;
```

## Understanding Monitoring

### Metrics Types

1. **Counters** - Always increasing (login attempts, transactions)
2. **Gauges** - Can go up/down (active sessions, account balance)
3. **Histograms** - Distribution of values (response times, transaction amounts)

### Alert Flow

```
1. Prometheus scrapes /metrics every 15s
2. Prometheus evaluates alert rules every 15s
3. If condition met for specified duration (for: 1m)
4. Prometheus fires alert to Alertmanager
5. Alertmanager groups, routes, and sends notifications
6. Alerts visible in Prometheus and Grafana
```

### Audit vs Metrics

**Audit Logs** (Database)
- Detailed event records
- Who, what, when, where
- Long-term storage
- Query for investigations

**Metrics** (Prometheus)
- Aggregated statistics
- Real-time monitoring
- Short-term retention
- Alerting and dashboards

## Testing Your Understanding

Ensure you can:

1. ✅ Access Prometheus, Grafana, and Alertmanager
2. ✅ View metrics from the API
3. ✅ Trigger and view alerts
4. ✅ Create custom Grafana dashboards
5. ✅ Query audit logs
6. ✅ Understand metric types

## Discussion Questions

1. **Metrics vs Logs**
   - When to use metrics vs logs?
   - What about traces?
   - How to correlate them?

2. **Alert Fatigue**
   - Too many alerts vs too few?
   - How to prioritize alerts?
   - When to page someone?

3. **Data Retention**
   - How long to keep audit logs?
   - Metrics retention policy?
   - Compliance requirements?

4. **Privacy Concerns**
   - What should NOT be logged?
   - GDPR implications?
   - Log sanitization?

## Congratulations! 🎉

✅ You've completed all 6 parts of the AAA Security guide!

You now have a fully functional banking API with:

### Authentication ✅
- Username/password login
- Google OAuth 2.0
- JWT tokens (access + refresh)
- Account lockout after failed attempts

### Authorization ✅
- Role-Based Access Control (RBAC)
- Attribute-Based Access Control (ABAC)
- Fine-grained permissions
- Context-aware policies

### Accounting ✅
- Prometheus metrics collection
- Grafana visualization
- Alertmanager notifications
- Comprehensive audit logging

## Next Steps

### For Students
1. Experiment with the API
2. Create custom dashboards
3. Add new ABAC policies
4. Implement 2FA
5. Add email notifications

### For Production
1. Use HTTPS everywhere
2. Set up proper SMTP for alerts
3. Implement rate limiting
4. Add database backups
5. Set up CI/CD pipeline
6. Deploy to cloud (AWS, GCP, Azure)
7. Use secrets manager
8. Implement log shipping (ELK stack)

## Additional Resources

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Tutorials](https://grafana.com/tutorials/)
- [OWASP Security Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Observability Engineering Book](https://www.honeycomb.io/observability-engineering-book)

---

**Thank you for completing this tutorial!** 

You now understand the fundamentals of AAA security and can build secure, monitored applications.
