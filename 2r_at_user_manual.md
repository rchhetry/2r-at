# 2R-AT Security Platform User & Administrator Manual

## Table of Contents

### User Guide
1. [Getting Started](#getting-started)
2. [Dashboard Overview](#dashboard-overview)
3. [Running Security Scans](#running-security-scans)
4. [Understanding Results](#understanding-results)
5. [Managing Scan History](#managing-scan-history)
6. [Generating Reports](#generating-reports)
7. [Account Management](#account-management)

### Administrator Guide
8. [System Administration](#system-administration)
9. [User Management](#user-management)
10. [Platform Monitoring](#platform-monitoring)
11. [Backup & Recovery](#backup--recovery)
12. [Security Hardening](#security-hardening)
13. [Performance Optimization](#performance-optimization)
14. [Troubleshooting](#troubleshooting)

---

## User Guide

### Getting Started

#### Creating Your Account

1. **Navigate to the Platform**
   - Open your web browser and go to your organization's 2R-AT platform URL
   - Click the "Register" button in the top-right corner

2. **Fill Out Registration Form**
   - **Full Name**: Enter your complete name
   - **Email Address**: Use a valid business email address
   - **Company**: Enter your organization name (optional)
   - **Password**: Create a strong password (minimum 8 characters)

3. **Account Verification**
   - Check your email for a verification message (if enabled)
   - Click the verification link to activate your account

#### First Login

1. **Access the Platform**
   - Go to the platform URL
   - Click "Login" and enter your credentials

2. **Initial Setup**
   - Complete your profile information
   - Review your scan quota and plan details
   - Familiarize yourself with the dashboard

### Dashboard Overview

The dashboard provides an at-a-glance view of your security scanning activities:

#### Statistics Cards
- **Total Scans**: Number of scans you've run
- **Completed**: Successfully finished scans
- **Quota Remaining**: Available scans in your current period

#### Recent Scans Section
- View your most recent scanning activities
- See scan status (Queued, Running, Completed, Failed)
- Quick access to scan results

#### Quick Actions
- Start a new scan directly from the dashboard
- Access your scan history
- Download recent reports

### Running Security Scans

#### Starting a New Scan

1. **Basic Scan Setup**
   - Click "Start New Scan" from the dashboard
   - Enter the **Target URL or IP Address**
     - Examples: `https://mywebsite.com`, `192.168.1.100`, `subdomain.company.com`
   - Provide a **Scan Name** (optional but recommended)
     - Example: "Monthly Security Assessment - Production Site"

2. **Advanced Options**
   - **Severity Filter**: Choose which vulnerability levels to scan for
     - `All Severities`: Comprehensive scan (recommended)
     - `Critical Only`: Focus on critical vulnerabilities
     - `High & Critical`: Skip low-severity issues
     - `Medium & Above`: Exclude informational findings
   
   - **Tags**: Specify vulnerability types to focus on
     - Examples: `cve,sqli,xss` for common web vulnerabilities
     - `ssl,tls` for SSL/TLS configuration issues
     - `dns,subdomain` for DNS-related vulnerabilities
   
   - **Templates**: Advanced users can specify Nuclei template categories
     - Leave blank for automatic selection

3. **Starting the Scan**
   - Review your settings
   - Click "Start Scan"
   - The scan will be queued and begin processing

#### Scan Types and Use Cases

**Production Website Scan**
```
Target: https://mycompany.com
Name: "Production Site - Weekly Security Check"
Severity: Medium & Above
Tags: cve,sqli,xss,ssl
```

**Internal Network Scan**
```
Target: 192.168.1.10
Name: "Internal Server Security Assessment"
Severity: All Severities
Tags: network,service,ssl
```

**Subdomain Discovery**
```
Target: company.com
Name: "Subdomain Security Review"
Severity: All Severities
Tags: subdomain,dns,ssl
```

#### Understanding Scan Status

- **Queued**: Scan is waiting to start
- **Running**: Scan is actively in progress
- **Completed**: Scan finished successfully
- **Failed**: Scan encountered an error

### Understanding Results

#### Vulnerability Severity Levels

**Critical (🔴)**
- Immediate threat to security
- Can lead to complete system compromise
- Examples: SQL injection, remote code execution
- **Action Required**: Fix immediately

**High (🟠)**
- Serious security risk
- Could lead to significant data breach
- Examples: Authentication bypass, privilege escalation
- **Action Required**: Fix within 24-48 hours

**Medium (🟡)**
- Moderate security concern
- Could be exploited in combination with other issues
- Examples: Cross-site scripting (XSS), information disclosure
- **Action Required**: Fix within 1-2 weeks

**Low (🟢)**
- Minor security issue
- Low risk of exploitation
- Examples: Missing security headers, weak SSL configuration
- **Action Required**: Fix during next maintenance window

**Info (🔵)**
- Informational findings
- No immediate security risk
- Examples: Software version disclosure, banner information
- **Action Required**: Consider for hardening

#### Vulnerability Details

Each vulnerability includes:

- **Template ID**: Nuclei template identifier
- **CVE ID**: Common Vulnerabilities and Exposures identifier (if applicable)
- **CVSS Score**: Common Vulnerability Scoring System rating (0-10)
- **Description**: Detailed explanation of the vulnerability
- **Matched URL**: Specific location where vulnerability was found
- **References**: Links to additional information
- **Fix Recommendation**: Guidance on how to resolve the issue

#### Reading Scan Results

1. **Summary View**
   - Review the vulnerability count by severity
   - Focus on critical and high-severity issues first
   - Note the total number of findings

2. **Detailed Results**
   - Click on individual vulnerabilities for details
   - Review the affected URLs/endpoints
   - Read the fix recommendations carefully

3. **False Positive Identification**
   - Some findings may not apply to your specific configuration
   - Mark false positives for future reference
   - Consult with your security team when in doubt

### Managing Scan History

#### Viewing Scan History

1. **Access Your Scans**
   - The dashboard shows recent scans automatically
   - Click "View All Scans" for complete history

2. **Scan Information**
   - **Target**: What was scanned
   - **Date/Time**: When the scan was performed
   - **Duration**: How long the scan took
   - **Status**: Current state of the scan
   - **Vulnerabilities**: Number of issues found

3. **Filtering and Sorting**
   - Filter by status (Completed, Failed, etc.)
   - Sort by date, target, or number of vulnerabilities
   - Search by scan name or target

#### Organizing Scans

**Best Practices:**
- Use descriptive scan names
- Include dates in scan names for recurring scans
- Group related scans (e.g., "Production-Weekly", "Staging-PreRelease")
- Tag scans by project or system

### Generating Reports

#### Downloading Individual Scan Reports

1. **HTML Reports** (Default)
   - Comprehensive, web-friendly format
   - Includes all vulnerability details
   - Easy to share with teams

2. **PDF Reports** (If available)
   - Professional format for executives
   - Suitable for compliance documentation
   - Print-friendly

#### Report Contents

**Executive Summary**
- High-level overview of findings
- Risk assessment
- Recommended actions

**Technical Details**
- Complete vulnerability listings
- Technical descriptions
- Remediation guidance

**Appendices**
- Scan configuration
- Methodology information
- Reference materials

#### Sharing Reports

**Internal Sharing**
- Download reports to share with development teams
- Use HTML format for technical teams
- Use PDF format for management

**External Sharing**
- Remove sensitive information before sharing outside organization
- Consider redacting internal URLs/IPs
- Follow your organization's data sharing policies

### Account Management

#### Profile Settings

1. **Personal Information**
   - Update name, email, company information
   - Change password regularly
   - Keep contact information current

2. **Notification Preferences**
   - Email notifications for scan completion
   - Alert preferences for critical findings
   - Weekly/monthly summary reports

#### Understanding Your Plan

**Scan Quotas**
- Monthly limit on number of scans
- Quota resets on the first of each month
- Contact admin for quota increases

**Plan Features**
- Basic: Limited scans, standard features
- Premium: Higher quotas, advanced reporting
- Enterprise: Unlimited scans, priority support

---

## Administrator Guide

### System Administration

#### Platform Overview

The 2R-AT platform consists of several key components:

- **Web Server (Apache)**: Serves the frontend and handles SSL
- **API Server (Flask)**: Processes requests and manages scans
- **Database (SQLite)**: Stores user data, scan results, and configuration
- **Scanner Engine (Nuclei)**: Performs vulnerability scans
- **Cache/Queue (Redis)**: Manages scan queue and sessions
- **Worker Processes**: Execute scans in background

#### Administrative Access

**Default Admin Account**
- Email: `admin@2r-at.com`
- Password: `admin123` (change immediately after first login)

**Admin Functions**
- User management and permissions
- Platform statistics and monitoring
- System configuration
- Backup and maintenance operations

#### System Requirements

**Minimum Requirements**
- 4 GB RAM
- 20 GB storage
- 2 CPU cores
- RedHat Enterprise Linux 8+ (or compatible)

**Recommended for Production**
- 8 GB RAM
- 100 GB storage
- 4 CPU cores
- SSL certificate
- Regular backup schedule

### User Management

#### User Accounts

**Creating Users**
1. Access admin panel
2. Navigate to User Management
3. Click "Add User"
4. Fill out user details:
   - Name, email, company
   - Initial password (user should change)
   - Role assignment
   - Plan/quota settings

**User Roles**
- **User**: Standard access, can run scans and view results
- **Admin**: Full platform access, user management, system settings

**Managing User Quotas**
- Set monthly scan limits per user
- Adjust quotas based on user needs
- Monitor quota usage and trends

#### User Account Actions

**Account Status**
- Activate/deactivate accounts
- Reset passwords
- Unlock locked accounts

**Usage Monitoring**
- View user scan history
- Monitor quota consumption
- Identify heavy users

**Bulk Operations**
- Import users from CSV
- Bulk quota adjustments
- Mass email notifications

### Platform Monitoring

#### Health Monitoring

Use the advanced monitoring script for comprehensive health checks:

```bash
# Quick status check
/usr/local/bin/2r-at-advanced-monitor.sh status

# Detailed monitoring
/usr/local/bin/2r-at-advanced-monitor.sh monitor

# View active alerts
/usr/local/bin/2r-at-advanced-monitor.sh alerts
```

#### Key Metrics to Monitor

**System Resources**
- CPU usage (keep below 80%)
- Memory usage (keep below 85%)
- Disk space (keep below 90%)
- Network connectivity

**Application Performance**
- API response times
- Scan queue length
- Database query performance
- Error rates

**Security Metrics**
- Failed login attempts
- Unusual access patterns
- SSL certificate expiration
- Security event logs

#### Setting Up Alerts

**Email Alerts**
1. Configure SMTP settings in `/etc/2r-at/monitoring.conf`
2. Set alert thresholds
3. Test alert delivery

**Slack Integration** (Optional)
1. Create Slack webhook URL
2. Add webhook to monitoring configuration
3. Test notifications

#### Log Management

**Important Log Files**
- Application: `/var/log/2r-at/scanner.log`
- Web Server: `/var/log/httpd/2r-at_*.log`
- System: `journalctl -u 2r-at-scanner`
- Database: `/var/log/2r-at/database.log`

**Log Rotation**
- Logs automatically rotate daily
- Compressed logs kept for 30 days
- Adjust retention in `/etc/logrotate.d/2r-at`

### Backup & Recovery

#### Automated Backups

The platform automatically creates backups:

- **Daily**: Every day at 3 AM
- **Weekly**: Sundays at 4 AM
- **Monthly**: First day of month at 5 AM

**Backup Locations**
- Database backups: `/opt/backups/2r-at/`
- System configs: Included in database backups
- Scan results: `/var/www/html/scan-results/`

#### Manual Backup Operations

```bash
# Create immediate backup
/usr/local/bin/2r-at-database-manager.sh backup manual

# List available backups
/usr/local/bin/2r-at-database-manager.sh list-backups

# Create emergency backup before maintenance
/usr/local/bin/2r-at-database-manager.sh backup emergency
```

#### Disaster Recovery

**Complete System Recovery**
1. Stop all services
2. Restore from latest good backup
3. Verify database integrity
4. Restart services
5. Run integration tests

**Partial Recovery**
- Database corruption: Restore from backup
- Service failures: Restart affected services
- Configuration issues: Restore config files

#### Backup Best Practices

- Test backup restoration regularly
- Store backups off-site for disaster recovery
- Encrypt backups containing sensitive data
- Document recovery procedures
- Monitor backup success/failure

### Security Hardening

#### SSL/TLS Configuration

**Installing SSL Certificates**
```bash
# Using Let's Encrypt (recommended)
certbot --apache -d yourdomain.com

# Enable HTTPS redirect
/usr/local/bin/2r-at-apache-deploy.sh enable-ssl
```

**SSL Best Practices**
- Use strong cipher suites
- Enable HSTS headers
- Regular certificate renewal
- Monitor certificate expiration

#### Firewall Configuration

**Basic Firewall Rules**
```bash
# Check current rules
firewall-cmd --list-all

# Allow HTTP/HTTPS only
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
```

**Advanced Security**
- IP whitelisting for admin access
- Rate limiting for API endpoints
- Intrusion detection systems
- Regular security updates

#### User Security

**Password Policies**
- Minimum 8 characters
- Require complexity (numbers, symbols)
- Force regular password changes
- Prevent password reuse

**Session Management**
- Automatic session timeout
- Secure session cookies
- Session invalidation on logout

#### Database Security

**Access Controls**
- Database file permissions (664)
- Application-only database access
- Regular permission audits

**Data Protection**
- Encrypt sensitive data at rest
- Secure backup storage
- Regular security scans of database

### Performance Optimization

#### System Performance

**CPU Optimization**
- Monitor scan worker processes
- Adjust concurrent scan limits
- Optimize Nuclei template usage

**Memory Management**
- Monitor application memory usage
- Restart services to clear memory leaks
- Optimize database queries

**Storage Optimization**
- Regular database maintenance
- Clean old scan results
- Compress log files

#### Application Tuning

**Scan Performance**
```bash
# Reduce concurrent scans if system is overloaded
systemctl stop 2r-at-worker@3
systemctl stop 2r-at-worker@4

# Monitor system resources during scans
htop
iotop
```

**Database Optimization**
```bash
# Regular maintenance
/usr/local/bin/2r-at-database-manager.sh maintain

# Check database performance
sqlite3 /var/lib/2r-at/scanner.db "EXPLAIN QUERY PLAN SELECT * FROM scans WHERE status = 'running';"
```

#### Capacity Planning

**Growth Monitoring**
- Track user growth trends
- Monitor scan volume increases
- Plan storage expansion

**Resource Scaling**
- Vertical scaling: Increase RAM/CPU
- Horizontal scaling: Additional servers
- Load balancing for high availability

### Troubleshooting

#### Common Issues and Solutions

**Platform Won't Start**
1. Check service status: `systemctl status 2r-at-scanner httpd redis`
2. Review logs: `journalctl -u 2r-at-scanner -f`
3. Verify database: `/usr/local/bin/2r-at-database-manager.sh check`
4. Check disk space: `df -h`

**Scans Not Starting**
1. Check Nuclei installation: `nuclei -version`
2. Verify worker processes: `systemctl status 2r-at-worker@*`
3. Check scan queue: `redis-cli LLEN scan_queue`
4. Review permissions: `ls -la /var/www/html/scan-results`

**Performance Issues**
1. Monitor resources: `htop`, `iotop`
2. Check database size: `du -h /var/lib/2r-at/scanner.db`
3. Review log file sizes: `du -sh /var/log/2r-at/`
4. Clear old data: `/usr/local/bin/2r-at-database-manager.sh maintain`

**Database Problems**
1. Check integrity: `sqlite3 /var/lib/2r-at/scanner.db "PRAGMA integrity_check;"`
2. Backup current state: `/usr/local/bin/2r-at-database-manager.sh backup emergency`
3. Restore from backup if corrupted
4. Check file permissions: `ls -la /var/lib/2r-at/scanner.db`

#### Diagnostic Tools

**Built-in Diagnostics**
```bash
# Comprehensive health check
/usr/local/bin/2r-at-advanced-monitor.sh status

# Integration tests
/usr/local/bin/2r-at-integration-test.sh quick

# Quick system overview
/usr/local/bin/2r-at-quick-reference.sh
```

**System Diagnostics**
```bash
# Service status
systemctl status httpd redis 2r-at-scanner

# Resource usage
free -h
df -h
top

# Network connectivity
netstat -tuln | grep -E ':80|:443|:6379'
curl http://127.0.0.1:5000/api/health
```

#### Getting Support

**Before Contacting Support**
1. Gather system information:
   - OS version: `cat /etc/redhat-release`
   - Platform version: Check deployment logs
   - Error messages from logs
   - Recent changes to system

2. Run diagnostics:
   - Health check results
   - Integration test results
   - System resource status

3. Document the issue:
   - When did it start?
   - What changed recently?
   - Steps to reproduce
   - Impact on users

**Support Channels**
- Email: support@2r-at.com
- Documentation: Internal knowledge base
- Emergency: Follow organization's escalation procedures

---

## Best Practices Summary

### For Users
- Use descriptive scan names
- Start with medium severity scans for new targets
- Review all critical and high vulnerabilities promptly
- Keep track of remediation efforts
- Run regular scans of important assets

### For Administrators
- Monitor system health daily
- Keep the platform updated
- Maintain regular backups
- Monitor user activity and resource usage
- Document all configuration changes
- Test disaster recovery procedures regularly

### Security Guidelines
- Change default passwords immediately
- Enable SSL/HTTPS for all access
- Regularly update all system components
- Monitor logs for security events
- Implement proper access controls
- Follow the principle of least privilege

---

## Appendices

### A. Default Ports and Services

| Service | Port | Purpose |
|---------|------|---------|
| HTTP | 80 | Web interface (redirects to HTTPS) |
| HTTPS | 443 | Secure web interface |
| Redis | 6379 | Internal cache and queue |
| API | 5000 | Internal API (proxied through Apache) |

### B. File Locations

| Component | Location |
|-----------|----------|
| Application | `/opt/2r-at-scanner/` |
| Database | `/var/lib/2r-at/scanner.db` |
| Web Files | `/var/www/html/` |
| Logs | `/var/log/2r-at/` |
| Backups | `/opt/backups/2r-at/` |
| Configuration | `/etc/2r-at/` |

### C. Important Commands Quick Reference

```bash
# Service Management
systemctl start/stop/restart 2r-at-scanner
systemctl status httpd redis 2r-at-scanner

# Health Monitoring
/usr/local/bin/2r-at-advanced-monitor.sh status
/usr/local/bin/2r-at-quick-reference.sh

# Database Operations
/usr/local/bin/2r-at-database-manager.sh check
/usr/local/bin/2r-at-database-manager.sh backup manual

# Testing
/usr/local/bin/2r-at-integration-test.sh quick

# Apache Management
/usr/local/bin/2r-at-apache-deploy.sh status
/usr/local/bin/2r-at-apache-deploy.sh reload
```

---

**Document Version:** 1.0  
**Last Updated:** January 2024  
**Platform Version:** 2R-AT v2.1.0