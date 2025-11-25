# Common Issues and Solutions

This document covers common problems students may encounter while following the Banking API tutorial.

## General Docker Issues

### Port Already in Use

**Error:**
```
Error starting userland proxy: listen tcp4 0.0.0.0:3000: bind: address already in use
```

**Solution:**
```bash
# Find what's using the port
sudo lsof -i :3000

# Kill the process or change port in .env
PORT=3001
```

### Container Keeps Restarting

**Check logs:**
```bash
docker-compose logs api
```

**Common causes:**
1. Database not ready → Wait for MySQL healthcheck
2. Missing dependencies → Run `docker-compose up --build`
3. Syntax errors → Check the logs for specific errors

### Can't Connect to Database

**Error:**
```
❌ Database connection failed: getaddrinfo ENOTFOUND mysql
```

**Solution:**
1. Ensure MySQL container is running: `docker-compose ps`
2. Check healthcheck: `docker-compose logs mysql`
3. Verify `DB_HOST=mysql` in `.env` (not `localhost`)
4. Restart API: `docker-compose restart api`

## Part 1 Issues

### Tables Not Created

**Check if init.sql ran:**
```bash
docker exec -it banking-mysql mysql -u root -p
# Password: rootpass123

SHOW DATABASES;
USE banking_db;
SHOW TABLES;
```

**If tables missing:**
```bash
# Remove volume and recreate
docker-compose down -v
docker-compose up --build -d
```

## Part 2 Issues

### "Module not found" Errors

**Error:**
```
Error: Cannot find module './utils/hashPassword'
```

**Solution:**
Ensure directories exist:
```bash
mkdir -p api/src/utils
mkdir -p api/src/services
mkdir -p api/src/middleware
```

### bcrypt Installation Fails

**Error during docker build:**
```
gyp ERR! build error
```

**Solution:**
Update Dockerfile to include build dependencies:
```dockerfile
FROM node:18-alpine

# Add build dependencies for native modules
RUN apk add --no-cache python3 make g++

WORKDIR /app
# ... rest of Dockerfile
```

### JWT Token Expired Immediately

**Check system time:**
```bash
# In container
docker exec -it banking-api date

# On host
date
```

If times don't match, restart Docker Desktop or sync time.

## Part 3 Issues

### "redirect_uri_mismatch" Error

**Google OAuth error:**
```
Error 400: redirect_uri_mismatch
```

**Solution:**
1. Go to Google Cloud Console
2. Check Authorized redirect URIs exactly matches:
   - `http://localhost:3000/api/auth/google/callback`
3. No trailing slash
4. Must use `http://` for localhost

### Session Required Error

**Error:**
```
Error: passport.initialize() middleware not in use
```

**Solution:**
Ensure app.js includes:
```javascript
app.use(passport.initialize());
```

### "Email not provided by Google"

**Solution:**
In Google Cloud Console:
1. Go to OAuth consent screen
2. Ensure "email" scope is added
3. In `passport.js`, verify scope includes 'email':
   ```javascript
   scope: ['profile', 'email']
   ```

## Part 4 Issues

### "Insufficient permissions" for Valid User

**Check role assignment:**
```sql
USE banking_db;

SELECT u.username, r.name as role 
FROM users u
LEFT JOIN user_roles ur ON u.id = ur.user_id
LEFT JOIN roles r ON ur.role_id = r.id
WHERE u.username = 'alice_customer';
```

**If no role:**
```sql
INSERT INTO user_roles (user_id, role_id) 
SELECT u.id, r.id 
FROM users u, roles r 
WHERE u.username = 'alice_customer' AND r.name = 'customer';
```

### Models Not Found

**Error:**
```
Error: Cannot find module '../models/Account'
```

**Solution:**
```bash
mkdir -p api/src/models
# Then create Account.js and Transaction.js files
```

## Part 5 Issues

### Daily Limit Always Blocks

**Check user attributes:**
```sql
SELECT * FROM user_attributes WHERE user_id = 1;
```

**If missing:**
```sql
INSERT INTO user_attributes (user_id, attribute_key, attribute_value) VALUES
(1, 'daily_transfer_limit', '1000');
```

### ABAC Middleware Order Matters

**Correct order in routes:**
```javascript
router.post('/transfer', 
  authenticate,              // 1. Verify JWT
  requirePermission('...'),  // 2. Check RBAC
  checkTransactionPermission,// 3. Check ABAC
  transactionController.transfer
);
```

## Part 6 Issues

### Prometheus Can't Scrape Metrics

**Error in Prometheus logs:**
```
context deadline exceeded
```

**Solution:**
1. Check API is running: `curl http://localhost:3000/metrics`
2. Verify `prometheus.yml` has correct target: `api:3000`
3. Ensure API and Prometheus are on same network
4. Restart Prometheus: `docker-compose restart prometheus`

### Grafana Can't Connect to Prometheus

**Error:**
```
Bad Gateway
```

**Solution:**
1. Check datasource URL: `http://prometheus:9090` (not `localhost`)
2. Verify Prometheus is running: `docker-compose ps prometheus`
3. Test connection: `docker exec -it banking-grafana wget http://prometheus:9090/api/v1/query`

### No Alerts Firing

**Check alert rules:**
```bash
# Open Prometheus
http://localhost:9090/alerts

# Check if rule is loaded
http://localhost:9090/config
```

**Common issues:**
1. Alert rule syntax error → Check `alerts.yml`
2. Not enough data points → Wait or generate test data
3. `for` duration not met → Reduce to `for: 30s` for testing

### Metrics Not Updating

**Check if metrics middleware is active:**
```bash
curl http://localhost:3000/metrics | grep http_requests_total
```

**If empty:**
1. Ensure `metricsMiddleware` is in app.js
2. Verify it's before routes
3. Make some API requests to generate metrics

## Database Issues

### Connection Pool Exhausted

**Error:**
```
Too many connections
```

**Solution:**
```javascript
// In database.js, increase pool size
const pool = mysql.createPool({
  // ...
  connectionLimit: 20, // Increase from 10
  queueLimit: 0
});
```

### Deadlock Detected

**Error during transfer:**
```
Deadlock found when trying to get lock
```

**Solution:**
Use transactions properly:
```javascript
const connection = await db.getConnection();
await connection.beginTransaction();

try {
  // Perform operations
  await connection.commit();
} catch (error) {
  await connection.rollback();
  throw error;
} finally {
  connection.release();
}
```

## Testing Issues

### curl Commands Not Working

**On Windows:**
Use PowerShell or install curl:
```powershell
Invoke-WebRequest -Method POST -Uri "http://localhost:3000/api/auth/login" `
  -Headers @{"Content-Type"="application/json"} `
  -Body '{"username":"alice","password":"SecurePass123!"}'
```

Or use Postman, Insomnia, or Thunder Client.

### jq Command Not Found

**Install jq:**
```bash
# macOS
brew install jq

# Ubuntu/Debian
sudo apt-get install jq

# Windows (Git Bash)
curl -L -o /usr/bin/jq.exe https://github.com/stedolan/jq/releases/latest/download/jq-win64.exe
```

## Performance Issues

### API Slow to Respond

**Check:**
1. Database query performance: Use `EXPLAIN` in MySQL
2. Missing indexes: Add indexes to frequently queried columns
3. Too many logs: Reduce console.log in production
4. Docker resources: Increase Docker Desktop memory/CPU

### Container Using Too Much Memory

**Monitor:**
```bash
docker stats
```

**Solution:**
```yaml
# In docker-compose.yml, add resource limits
services:
  api:
    # ...
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
```

## Getting Help

1. **Check Logs:** `docker-compose logs -f [service-name]`
2. **Inspect Container:** `docker exec -it banking-api sh`
3. **Database Console:** `docker exec -it banking-mysql mysql -u root -p`
4. **Network Issues:** `docker network inspect api-app-tutorial_banking-network`
5. **Clean Restart:** `docker-compose down -v && docker-compose up --build`

## Debugging Tips

### Enable Debug Logging

Add to `.env`:
```env
DEBUG=*
LOG_LEVEL=debug
```

### Check All Services Status

```bash
docker-compose ps
docker-compose logs --tail=50
```

### Test Database Connection

```bash
docker exec -it banking-mysql mysqladmin -u root -p ping
```

### Verify Environment Variables

```bash
docker exec -it banking-api env | grep DB_
```

### Test Network Connectivity

```bash
# From API container to MySQL
docker exec -it banking-api ping mysql

# From API container to Prometheus
docker exec -it banking-api wget http://prometheus:9090/-/healthy
```

---

**Still having issues?** Review the specific part of the tutorial again, check the prerequisites, and ensure each step was completed before moving to the next part.
