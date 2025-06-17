# 2R-AT Security Platform Troubleshooting Guide

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Common Issues](#common-issues)
3. [Service Issues](#service-issues)
4. [Database Issues](#database-issues)
5. [Scanning Issues](#scanning-issues)
6. [Network and SSL Issues](#network-and-ssl-issues)
7. [Performance Issues](#performance-issues)
8. [Security Issues](#security-issues)
9. [Log Analysis](#log-analysis)
10. [Recovery Procedures](#recovery-procedures)

## Quick Diagnostics

### System Health Check
```bash
# Run comprehensive health check
/usr/local/bin/2r-at-advanced-monitor.sh status

# Check all services
systemctl status httpd redis 2r-at-scanner firewalld

# Quick database check
/usr/local/bin/2r-at-database-manager.sh check

# Test API connectivity
curl -s http://127.0.0.1:5000/api/health | python3 -m json.tool
```

### First Steps for Any Issue
1. **Check service status**: `systemctl status 2r-at-scanner httpd redis`
2. **Review recent logs**: `journalctl -u 2r-at-scanner --since "10 minutes ago"`
3. **Test basic connectivity**: `curl http://127.0.0.1:5000/api/health`
4. **Check disk space**: `df -h /var/lib/2r-at /var/log/2r-at`
5. **Verify database**: `sqlite3 /var/lib/2r-at/scanner.db "SELECT 1;"`

## Common Issues

### Issue: "Cannot connect to 2R-AT platform"

**Symptoms:**
- Website doesn't load
- API returns connection errors
- Users can't access the platform

**Diagnosis:**
```bash
# Check if services are running
systemctl status httpd 2r-at-scanner

# Check network connectivity
netstat -tuln | grep -E ':80|:443|:5000'

# Test local connectivity
curl -I http://127.0.0.1
curl -I http://127.0.0.1:5000/api/health
```

**Solutions:**
1. **Start missing services:**
   ```bash
   systemctl start httpd
   systemctl start 2r-at-scanner
   systemctl enable httpd 2r-at-scanner
   ```

2. **Check firewall:**
   ```bash
   firewall-cmd --list-services
   firewall-cmd --permanent --add-service=http
   firewall-cmd --permanent --add-service=https
   firewall-cmd --reload
   ```

3. **Verify SELinux context:**
   ```bash
   setsebool -P httpd_can_network_connect 1
   restorecon -Rv /var/www/html/
   ```

### Issue: "Scans not starting or failing immediately"

**Symptoms:**
- Scans remain in "queued" status
- Scans fail with errors
- No scan results generated

**Diagnosis:**
```bash
# Check Nuclei installation
nuclei -version

# Check worker processes
systemctl status 2r-at-worker@*

# Check scan queue in database
sqlite3 /var/lib/2r-at/scanner.db "SELECT id, target, status, error_message FROM scans ORDER BY created_at DESC LIMIT 10;"

# Check worker logs
journalctl -u 2r-at-worker@1 --since "1 hour ago"
```

**Solutions:**
1. **Restart scanner service:**
   ```bash
   systemctl restart 2r-at-scanner
   ```

2. **Check Nuclei templates:**
   ```bash
   nuclei -update-templates
   nuclei -version
   ```

3. **Verify permissions:**
   ```bash
   chown -R apache:apache /var/www/html/scan-results
   chmod 755 /var/www/html/scan-results
   ```

4. **Clear stuck scans:**
   ```bash
   sqlite3 /var/lib/2r-at/scanner.db "UPDATE scans SET status = 'failed', error_message = 'Reset by admin' WHERE status = 'running' AND started_at < datetime('now', '-1 hour');"
   ```

### Issue: "Database errors or corruption"

**Symptoms:**
- API returns database errors
- Cannot create users or scans
- Data inconsistencies

**Diagnosis:**
```bash
# Check database integrity
sqlite3 /var/lib/2r-at/scanner.db "PRAGMA integrity_check;"

# Check database permissions
ls -la /var/lib/2r-at/scanner.db

# Test database connectivity
sqlite3 /var/lib/2r-at/scanner.db ".tables"
```

**Solutions:**
1. **Restore from backup:**
   ```bash
   /usr/local/bin/2r-at-database-manager.sh list-backups
   /usr/local/bin/2r-at-database-manager.sh restore /path/to/backup.db.gz
   ```

2. **Repair database:**
   ```bash
   # Create backup first
   /usr/local/bin/2r-at-database-manager.sh backup emergency

   # Try to repair
   sqlite3 /var/lib/2r-at/scanner.db "VACUUM;"
   sqlite3 /var/lib/2r-at/scanner.db "REINDEX;"
   ```

3. **Fix permissions:**
   ```bash
   chown apache:apache /var/lib/2r-at/scanner.db
   chmod 664 /var/lib/2r-at/scanner.db
   ```

## Service Issues

### 2R-AT Scanner Service Won't Start

**Check logs:**
```bash
journalctl -u 2r-at-scanner --since "5 minutes ago" -f
```

**Common causes and fixes:**

1. **Missing dependencies:**
   ```bash
   # Ensure Redis is running
   systemctl start redis
   systemctl enable redis

   # Check Python dependencies
   pip3 install flask flask-cors gunicorn redis
   ```

2. **Port conflicts:**
   ```bash
   # Check what's using port 5000
   netstat -tulpn | grep :5000
   
   # Kill conflicting process if needed
   fuser -k 5000/tcp
   ```

3. **Database issues:**
   ```bash
   # Check if database exists and is accessible
   test -r /var/lib/2r-at/scanner.db && echo "Database accessible" || echo "Database problem"
   
   # Reinitialize if needed
   /usr/local/bin/2r-at-database-manager.sh init
   ```

4. **Permission issues:**
   ```bash
   # Fix ownership
   chown -R apache:apache /opt/2r-at-scanner /var/lib/2r-at /var/log/2r-at
   
   # Fix executable permissions
   chmod +x /opt/2r-at-scanner/*.sh /opt/2r-at-scanner/*.py
   ```

### Apache/HTTP Issues

**Apache won't start:**
```bash
# Check Apache configuration
httpd -t

# Check for syntax errors
httpd -S

# Start Apache
systemctl start httpd
```

**Common fixes:**
1. **Configuration syntax errors:**
   ```bash
   # Test configuration
   httpd -t
   
   # Check virtual hosts
   httpd -S
   ```

2. **Port conflicts:**
   ```bash
   # Check what's using port 80/443
   netstat -tulpn | grep -E ':80|:443'
   ```

3. **SELinux issues:**
   ```bash
   # Check SELinux denials
   ausearch -m avc -ts recent
   
   # Allow HTTP network connections
   setsebool -P httpd_can_network_connect 1
   ```

### Redis Issues

**Redis won't start:**
```bash
# Check Redis logs
journalctl -u redis --since "5 minutes ago"

# Test Redis manually
redis-server --version
redis-cli ping
```

**Common fixes:**
1. **Memory issues:**
   ```bash
   # Check available memory
   free -h
   
   # Reduce Redis memory usage if needed
   echo "maxmemory 512mb" >> /etc/redis.conf
   ```

2. **Permission issues:**
   ```bash
   chown redis:redis /var/lib/redis
   chown redis:redis /var/log/redis
   ```

## Database Issues

### Database Corruption

**Symptoms:**
- SQLite error messages
- Data inconsistencies
- Application crashes

**Recovery steps:**
1. **Stop all services:**
   ```bash
   systemctl stop 2r-at-scanner
   ```

2. **Check integrity:**
   ```bash
   sqlite3 /var/lib/2r-at/scanner.db "PRAGMA integrity_check;"
   ```

3. **Create backup:**
   ```bash
   /usr/local/bin/2r-at-database-manager.sh backup emergency
   ```

4. **Try repair:**
   ```bash
   sqlite3 /var/lib/2r-at/scanner.db ".dump" > /tmp/db_dump.sql
   mv /var/lib/2r-at/scanner.db /var/lib/2r-at/scanner.db.corrupt
   sqlite3 /var/lib/2r-at/scanner.db < /tmp/db_dump.sql
   ```

5. **Restart services:**
   ```bash
   systemctl start 2r-at-scanner
   ```

### Database Performance Issues

**Symptoms:**
- Slow API responses
- Timeouts during operations
- High CPU usage

**Solutions:**
1. **Optimize database:**
   ```bash
   /usr/local/bin/2r-at-database-manager.sh maintain
   ```

2. **Check database size:**
   ```bash
   du -h /var/lib/2r-at/scanner.db
   
   # Clean old records if needed
   sqlite3 /var/lib/2r-at/scanner.db "DELETE FROM api_usage WHERE created_at < datetime('now', '-30 days');"
   ```

3. **Add indexes if missing:**
   ```bash
   sqlite3 /var/lib/2r-at/scanner.db ".indices"
   ```

## Scanning Issues

### Nuclei Scanner Problems

**Nuclei not found:**
```bash
# Check installation
which nuclei
nuclei -version

# Reinstall if needed
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
mv ~/go/bin/nuclei /usr/local/bin/nuclei
```

**Template issues:**
```bash
# Update templates
nuclei -update-templates

# Check template location
nuclei -templates-directory

# Manual template download
rm -rf ~/nuclei-templates
nuclei -update-templates
```

**Permission issues:**
```bash
# Ensure nuclei is executable
chmod +x /usr/local/bin/nuclei

# Check template permissions
chown -R apache:apache ~/nuclei-templates
```

### Scan Results Not Generated

**Check scan logs:**
```bash
tail -f /var/log/2r-at/scanner.log
journalctl -u 2r-at-worker@1 -f
```

**Common causes:**
1. **Network connectivity:**
   ```bash
   # Test target connectivity
   ping -c 4 target.com
   curl -I http://target.com
   ```

2. **Template issues:**
   ```bash
   # Test nuclei manually
   nuclei -target http://target.com -templates ~/nuclei-templates/http/
   ```

3. **Output directory permissions:**
   ```bash
   # Fix result directory permissions
   mkdir -p /var/www/html/scan-results
   chown apache:apache /var/www/html/scan-results
   chmod 755 /var/www/html/scan-results
   ```

## Network and SSL Issues

### SSL Certificate Problems

**Self-signed certificate warnings:**
```bash
# Generate proper certificates with Let's Encrypt
certbot --apache -d yourdomain.com

# Or create self-signed for testing
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/2r-at.key \
  -out /etc/ssl/certs/2r-at.crt
```

**Certificate expiration:**
```bash
# Check certificate expiry
openssl x509 -enddate -noout -in /etc/letsencrypt/live/yourdomain.com/cert.pem

# Auto-renewal
certbot renew --dry-run
```

### Firewall Issues

**Blocked connections:**
```bash
# Check firewall status
firewall-cmd --state
firewall-cmd --list-all

# Open required ports
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --permanent --add-port=5000/tcp  # If needed for direct API access
firewall-cmd --reload
```

**SELinux blocking connections:**
```bash
# Check SELinux denials
ausearch -m avc -ts recent

# Allow HTTP connections
setsebool -P httpd_can_network_connect 1

# Allow specific port if needed
semanage port -a -t http_port_t -p tcp 5000
```

## Performance Issues

### High CPU Usage

**Identify the cause:**
```bash
# Check top processes
top -c
htop

# Check specific services
systemctl status 2r-at-scanner
ps aux | grep -E '(nuclei|python|httpd)'
```

**Solutions:**
1. **Limit concurrent scans:**
   ```bash
   # Edit configuration to reduce workers
   systemctl stop 2r-at-worker@3
   systemctl stop 2r-at-worker@4
   ```

2. **Optimize Nuclei usage:**
   ```bash
   # Use severity filters
   # Limit template usage
   # Add rate limiting
   ```

### High Memory Usage

**Check memory usage:**
```bash
free -h
ps aux --sort=-%mem | head -10
```

**Solutions:**
1. **Restart services to clear memory leaks:**
   ```bash
   systemctl restart 2r-at-scanner
   systemctl restart httpd
   ```

2. **Optimize database:**
   ```bash
   /usr/local/bin/2r-at-database-manager.sh maintain
   ```

3. **Clear old scan results:**
   ```bash
   find /var/www/html/scan-results -name "*.html" -mtime +30 -delete
   find /var/www/html/scan-results -name "*.json" -mtime +30 -delete
   ```

### Disk Space Issues

**Check disk usage:**
```bash
df -h
du -sh /var/log/2r-at/*
du -sh /var/lib/2r-at/*
du -sh /opt/backups/2r-at/*
```

**Clean up:**
```bash
# Clean old logs
journalctl --vacuum-time=7d

# Clean old backups
/usr/local/bin/2r-at-database-manager.sh cleanup

# Clean old scan results
find /var/www/html/scan-results -mtime +30 -delete

# Clean temporary files
rm -rf /tmp/2r-at-*
```

## Security Issues

### Unauthorized Access Attempts

**Check for failed logins:**
```bash
journalctl --since "24 hours ago" | grep -i "failed\|invalid\|unauthorized"
tail -f /var/log/2r-at/scanner.log | grep -i "error\|fail"
```

**Harden security:**
```bash
# Update firewall rules
firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='SUSPICIOUS_IP' drop"

# Check for suspicious database entries
sqlite3 /var/lib/2r-at/scanner.db "SELECT * FROM security_events WHERE severity = 'critical';"
```

### API Security Issues

**Rate limiting not working:**
```bash
# Check Redis connectivity (needed for rate limiting)
redis-cli ping

# Test rate limiting
for i in {1..20}; do curl http://127.0.0.1:5000/api/health; done
```

**JWT token issues:**
```bash
# Check token expiration settings
grep -r "JWT_ACCESS_TOKEN_EXPIRES" /opt/2r-at-scanner/

# Clear expired sessions
redis-cli FLUSHDB
```

## Log Analysis

### Important Log Locations

```bash
# Application logs
tail -f /var/log/2r-at/scanner.log
tail -f /var/log/2r-at/monitoring.log
tail -f /var/log/2r-at/database.log

# System logs
journalctl -u 2r-at-scanner -f
journalctl -u httpd -f
journalctl -u redis -f

# Access logs
tail -f /var/log/httpd/access_log
tail -f /var/log/httpd/error_log
```

### Log Analysis Commands

```bash
# Find errors in the last hour
journalctl -u 2r-at-scanner --since "1 hour ago" | grep -i error

# Check scan failures
grep -i "failed\|error" /var/log/2r-at/scanner.log | tail -20

# Monitor real-time activity
tail -f /var/log/2r-at/scanner.log | grep -E "(SCAN|ERROR|WARN)"

# Check API performance
grep "GET\|POST" /var/log/httpd/access_log | tail -20
```

### Log Rotation Issues

```bash
# Check logrotate configuration
cat /etc/logrotate.d/2r-at

# Manually rotate logs if needed
logrotate -f /etc/logrotate.d/2r-at

# Check disk space for logs
du -sh /var/log/2r-at/
```

## Recovery Procedures

### Complete System Recovery

**If the entire system is compromised:**

1. **Stop all services:**
   ```bash
   systemctl stop 2r-at-scanner httpd
   ```

2. **Backup current state:**
   ```bash
   tar -czf /tmp/2r-at-emergency-backup.tar.gz \
     /var/lib/2r-at/ \
     /var/log/2r-at/ \
     /etc/2r-at/ \
     /opt/2r-at-scanner/
   ```

3. **Restore from known good backup:**
   ```bash
   /usr/local/bin/2r-at-database-manager.sh list-backups
   /usr/local/bin/2r-at-database-manager.sh restore /path/to/good/backup.db.gz
   ```

4. **Reinitialize if needed:**
   ```bash
   /usr/local/bin/2r-at-database-manager.sh init
   ```

5. **Restart services:**
   ```bash
   systemctl start httpd
   systemctl start 2r-at-scanner
   ```

6. **Verify operation:**
   ```bash
   /usr/local/bin/2r-at-integration-test.sh quick
   ```

### Database Recovery

**Complete database rebuild:**

1. **Export existing data (if possible):**
   ```bash
   /usr/local/bin/2r-at-database-manager.sh export csv
   ```

2. **Reinitialize database:**
   ```bash
   mv /var/lib/2r-at/scanner.db /var/lib/2r-at/scanner.db.broken
   /usr/local/bin/2r-at-database-manager.sh init
   ```

3. **Import critical data:**
   ```bash
   # Manual import of users/scans if needed
   # This would require custom scripting based on exported data
   ```

### Service Recovery

**Reset all services to clean state:**

```bash
# Stop everything
systemctl stop 2r-at-scanner httpd redis

# Clear runtime data
rm -rf /var/run/2r-at/*
rm -rf /tmp/2r-at-*

# Clear Redis data
redis-cli FLUSHALL

# Restart in order
systemctl start redis
systemctl start httpd  
systemctl start 2r-at-scanner

# Verify
/usr/local/bin/2r-at-advanced-monitor.sh status
```

## Emergency Contacts and Resources

### Getting Help

1. **Run diagnostics:**
   ```bash
   /usr/local/bin/2r-at-advanced-monitor.sh status > /tmp/diagnostic-report.txt
   /usr/local/bin/2r-at-integration-test.sh quick >> /tmp/diagnostic-report.txt
   ```

2. **Collect logs:**
   ```bash
   journalctl -u 2r-at-scanner --since "1 hour ago" > /tmp/service-logs.txt
   tail -50 /var/log/2r-at/scanner.log >> /tmp/service-logs.txt
   ```

3. **Check system resources:**
   ```bash
   df -h > /tmp/system-info.txt
   free -h >> /tmp/system-info.txt
   ps aux --sort=-%cpu | head -10 >> /tmp/system-info.txt
   ```

### Quick Reference Commands

```bash
# Emergency service restart
systemctl restart 2r-at-scanner httpd redis

# Emergency database backup
/usr/local/bin/2r-at-database-manager.sh backup emergency

# Emergency log cleanup
journalctl --vacuum-time=1d

# Emergency health check
curl -s http://127.0.0.1:5000/api/health

# Emergency monitoring
/usr/local/bin/2r-at-advanced-monitor.sh check

# Emergency test
/usr/local/bin/2r-at-integration-test.sh prerequisites
```

---

## Appendix: Configuration Files

### Important Configuration Locations

- **Main application**: `/opt/2r-at-scanner/`
- **Database**: `/var/lib/2r-at/scanner.db`
- **Logs**: `/var/log/2r-at/`
- **Backups**: `/opt/backups/2r-at/`
- **Web files**: `/var/www/html/`
- **Systemd services**: `/etc/systemd/system/2r-at*`

### Default Ports

- **HTTP**: 80
- **HTTPS**: 443
- **API**: 5000 (internal)
- **Redis**: 6379

### Key Processes

- **2r-at-scanner**: Main API service
- **2r-at-worker@***: Background scan workers
- **httpd**: Web server
- **redis**: Session and cache storage

Remember: Always create backups before making significant changes, and test changes in a development environment when possible.