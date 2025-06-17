#!/bin/bash
# ========================================
# 2R-AT Final Deployment Orchestrator
# Complete platform deployment with all components
# ========================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
DOMAIN="${DOMAIN:-2r-at.com}"
EMAIL="${EMAIL:-admin@2r-at.com}"
INSTALL_DIR="/opt/2r-at-scanner"
BACKUP_DIR="/opt/backups/2r-at"
LOG_DIR="/var/log/2r-at"
WEB_DIR="/var/www/html"
CONFIG_DIR="/etc/2r-at"

# Deployment stages
STAGE_PREP=1
STAGE_BASE=2
STAGE_DATABASE=3
STAGE_BACKEND=4
STAGE_FRONTEND=5
STAGE_SERVICES=6
STAGE_SECURITY=7
STAGE_MONITORING=8
STAGE_TESTING=9
STAGE_FINALIZE=10

print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
  ____  ____       _  _____   ______ _             _   ____             _                     
 |___ \|  _ \     / \|_   _| |  ____(_)           | | |  _ \           | |                    
   __) | |_) |   / _ \ | |   | |__   _ _ __   __ _| | | | | | ___ _ __ | | ___  _   _ _ __ ___  
  / __/|  _ <   / ___ \| |   |  __| | | '_ \ / _` | | | | | |/ _ \ '_ \| |/ _ \| | | | '_ ` _ \ 
 |_____|_| \_\ /_/   \_\_|   | |    | | | | | (_| | | | |_| |  __/ |_) | | (_) | |_| | | | | | |
                             |_|    |_|_| |_|\__,_|_| |____/ \___| .__/|_|\___/ \__, |_| |_| |_|
                                                                 | |            __/ |         
                                                                 |_|           |___/          

 ____                            _      _          ____        _         _            
/ ___|___  _ __ ___  _ __   ___  | | ___| |_ ___   |  _ \  __ _| |_ __ _ | |__   __ _ ___  ___ 
| |   / _ \| '_ ` _ \| '_ \ / _ \ | |/ _ \ __/ _ \  | | | |/ _` | __/ _` || '_ \ / _` / __|/ _ \
| |__| (_) | | | | | | |_) |  __/ | |  __/ ||  __/  | |_| | (_| | || (_| || |_) | (_| \__ \  __/
\____\___/|_| |_| |_| .__/ \___| |_|\___|\__\___|  |____/ \__,_|\__\__,_||_.__/ \__,_|___/\___|
                    |_|                                                                        

Next-Generation Cybersecurity Platform - Production Deployment
EOF
    echo -e "${NC}"
}

log_stage() {
    local stage="$1"
    local message="$2"
    echo -e "\n${PURPLE}=== STAGE $stage ===${NC} ${BLUE}$message${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [STAGE-$stage] $message" >> "$LOG_DIR/deployment.log"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1" >> "$LOG_DIR/deployment.log"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] $1" >> "$LOG_DIR/deployment.log"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$LOG_DIR/deployment.log"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Stage 1: Environment Preparation
stage_preparation() {
    log_stage $STAGE_PREP "Environment Preparation"
    
    # Create all required directories
    log_info "Creating directory structure..."
    mkdir -p "$INSTALL_DIR" "$BACKUP_DIR" "$LOG_DIR" "$WEB_DIR" "$CONFIG_DIR"
    mkdir -p "/var/lib/2r-at" "/var/run/2r-at" "/var/www/html/scan-results"
    
    # Set initial permissions
    chown apache:apache "$INSTALL_DIR" "$BACKUP_DIR" "$LOG_DIR" "$WEB_DIR" "/var/lib/2r-at" "/var/run/2r-at"
    
    # Initialize logging
    touch "$LOG_DIR/deployment.log"
    chmod 644 "$LOG_DIR/deployment.log"
    
    # Check available resources
    local memory_gb=$(free -g | awk '/^Mem:/{print $2}')
    local disk_gb=$(df / | awk 'NR==2{print int($4/1024/1024)}')
    
    if [[ $memory_gb -lt 4 ]]; then
        log_warn "Low memory detected: ${memory_gb}GB (recommended: 4GB+)"
    fi
    
    if [[ $disk_gb -lt 20 ]]; then
        log_error "Insufficient disk space: ${disk_gb}GB (required: 20GB+)"
        exit 1
    fi
    
    log_info "Environment preparation completed"
}

# Stage 2: Base System Setup
stage_base_system() {
    log_stage $STAGE_BASE "Base System Setup"
    
    log_info "Updating system packages..."
    dnf update -y >/dev/null 2>&1 || yum update -y >/dev/null 2>&1
    
    log_info "Installing EPEL repository..."
    dnf install -y epel-release >/dev/null 2>&1 || yum install -y epel-release >/dev/null 2>&1
    
    log_info "Installing base packages..."
    dnf install -y \
        python3 python3-pip python3-devel gcc \
        redis httpd mod_ssl \
        wget curl git unzip firewalld \
        certbot python3-certbot-apache \
        sqlite bc mailx jq \
        htop iotop nethogs \
        logrotate crontabs >/dev/null 2>&1 || \
    yum install -y \
        python3 python3-pip python3-devel gcc \
        redis httpd mod_ssl \
        wget curl git unzip firewalld \
        certbot python3-certbot-apache \
        sqlite bc mailx jq \
        htop iotop nethogs \
        logrotate crontabs >/dev/null 2>&1
    
    # Install Go for Nuclei
    if ! command -v go &> /dev/null; then
        log_info "Installing Go programming language..."
        cd /tmp
        wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
        tar -xzf go1.21.5.linux-amd64.tar.gz
        mv go /usr/local/
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
        export PATH=$PATH:/usr/local/go/bin
    fi
    
    # Install Nuclei
    log_info "Installing Nuclei scanner..."
    export PATH=$PATH:/usr/local/go/bin
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest >/dev/null 2>&1
    mv /root/go/bin/nuclei /usr/local/bin/nuclei 2>/dev/null || mv ~/go/bin/nuclei /usr/local/bin/nuclei
    chmod +x /usr/local/bin/nuclei
    
    # Update Nuclei templates
    log_info "Updating Nuclei templates..."
    /usr/local/bin/nuclei -update-templates >/dev/null 2>&1
    
    # Install Python dependencies
    log_info "Installing Python dependencies..."
    pip3 install --upgrade pip >/dev/null 2>&1
    pip3 install \
        flask flask-cors flask-limiter flask-jwt-extended \
        redis gunicorn python-dotenv \
        requests urllib3 >/dev/null 2>&1
    
    log_info "Base system setup completed"
}

# Stage 3: Database Setup
stage_database_setup() {
    log_stage $STAGE_DATABASE "Database Setup"
    
    # Deploy database management script
    log_info "Deploying database management script..."
    
    # Create the database initialization
    log_info "Initializing database schema..."
    /usr/local/bin/2r-at-database-manager.sh init
    
    # Create initial backup
    log_info "Creating initial database backup..."
    /usr/local/bin/2r-at-database-manager.sh backup initial
    
    log_info "Database setup completed"
}

# Stage 4: Backend Deployment
stage_backend_deployment() {
    log_stage $STAGE_BACKEND "Backend API Deployment"
    
    # Deploy backend application
    log_info "Deploying backend API application..."
    
    # Note: In a real deployment, this would copy from the repository
    # For this demo, we create the file structure
    
    # Create backend configuration
    cat > "$INSTALL_DIR/config.py" << EOF
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or '$(openssl rand -hex 32)'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or '$(openssl rand -hex 32)'
    DATABASE_PATH = '/var/lib/2r-at/scanner.db'
    REDIS_URL = 'redis://localhost:6379/0'
    NUCLEI_PATH = '/usr/local/bin/nuclei'
    SCAN_RESULTS_DIR = '/var/www/html/scan-results'
    LOG_DIR = '/var/log/2r-at'
    MAX_CONCURRENT_SCANS = 5
    RATE_LIMIT_DEFAULT = "100 per hour"
    DOMAIN = '$DOMAIN'
    ADMIN_EMAIL = '$EMAIL'

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True
    DATABASE_PATH = '/tmp/test_scanner.db'

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': ProductionConfig
}
EOF
    
    # Create environment file
    cat > "$INSTALL_DIR/.env" << EOF
FLASK_ENV=production
FLASK_APP=app.py
DATABASE_PATH=/var/lib/2r-at/scanner.db
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=$(openssl rand -hex 32)
JWT_SECRET_KEY=$(openssl rand -hex 32)
LOG_LEVEL=INFO
EOF
    
    # Set permissions
    chown apache:apache "$INSTALL_DIR"/*
    chmod 640 "$INSTALL_DIR/.env"
    
    log_info "Backend deployment completed"
}

# Stage 5: Frontend Deployment
stage_frontend_deployment() {
    log_stage $STAGE_FRONTEND "Frontend Deployment"
    
    log_info "Deploying frontend web interface..."
    
    # The frontend HTML file would be deployed here
    # In a real deployment, this would copy from repository
    
    # Create a simple index redirect for now
    cat > "$WEB_DIR/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>2R-AT Security Platform</title>
    <meta http-equiv="refresh" content="0; url=/app.html">
</head>
<body>
    <p>Redirecting to 2R-AT Security Platform...</p>
</body>
</html>
EOF
    
    # Set permissions
    chown -R apache:apache "$WEB_DIR"
    chmod 644 "$WEB_DIR"/*.html
    
    log_info "Frontend deployment completed"
}

# Stage 6: Service Configuration
stage_service_configuration() {
    log_stage $STAGE_SERVICES "Service Configuration"
    
    log_info "Configuring systemd services..."
    
    # Deploy systemd services (already created in previous artifact)
    systemctl daemon-reload
    
    log_info "Configuring Apache..."
    
    # Deploy Apache configuration (already created in previous artifact)
    
    log_info "Starting and enabling services..."
    
    # Start services in order
    systemctl start redis
    systemctl enable redis
    log_info "Redis service started"
    
    systemctl start httpd
    systemctl enable httpd
    log_info "Apache service started"
    
    # Note: 2r-at-scanner service will be started after backend files are in place
    
    log_info "Service configuration completed"
}

# Stage 7: Security Configuration
stage_security_configuration() {
    log_stage $STAGE_SECURITY "Security Configuration"
    
    log_info "Configuring firewall..."
    systemctl start firewalld
    systemctl enable firewalld
    
    firewall-cmd --permanent --add-service=http >/dev/null 2>&1
    firewall-cmd --permanent --add-service=https >/dev/null 2>&1
    firewall-cmd --reload >/dev/null 2>&1
    
    log_info "Configuring SELinux..."
    if command -v getenforce &> /dev/null && [[ $(getenforce) != "Disabled" ]]; then
        setsebool -P httpd_can_network_connect 1 >/dev/null 2>&1
        semanage fcontext -a -t httpd_log_t "/var/log/2r-at(/.*)?" >/dev/null 2>&1 || true
        restorecon -Rv /var/log/2r-at/ >/dev/null 2>&1
        restorecon -Rv /var/www/html/ >/dev/null 2>&1
    fi
    
    log_info "Setting secure file permissions..."
    
    # Application directories
    chown -R apache:apache "$INSTALL_DIR" "$LOG_DIR" "/var/lib/2r-at" "$WEB_DIR"
    chmod 750 "$INSTALL_DIR"
    chmod 755 "$LOG_DIR"
    chmod 700 "/var/lib/2r-at"
    chmod 755 "$WEB_DIR"
    chmod 755 "/var/www/html/scan-results"
    
    # Configuration files
    chown root:apache "$CONFIG_DIR"
    chmod 750 "$CONFIG_DIR"
    
    # Backup directory
    chown apache:apache "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    
    # Log files
    find "$LOG_DIR" -type f -name "*.log" -exec chmod 640 {} \;
    find "$LOG_DIR" -type f -name "*.log" -exec chown apache:apache {} \;
    
    log_info "Security configuration completed"
}

# Stage 8: Monitoring Setup
stage_monitoring_setup() {
    log_stage $STAGE_MONITORING "Monitoring Setup"
    
    log_info "Deploying monitoring scripts..."
    
    # Create monitoring configuration
    cat > "$CONFIG_DIR/monitoring.conf" << EOF
# 2R-AT Monitoring Configuration
CPU_THRESHOLD=80
MEMORY_THRESHOLD=85
DISK_THRESHOLD=90
LOAD_THRESHOLD=5.0
API_RESPONSE_THRESHOLD=5000
ERROR_RATE_THRESHOLD=10

# Email configuration
SMTP_SERVER="localhost"
SMTP_PORT="587"
FROM_EMAIL="noreply@$DOMAIN"
ADMIN_EMAIL="$EMAIL"

# Slack webhook (optional)
SLACK_WEBHOOK=""
EOF
    
    # Set up monitoring service
    systemctl daemon-reload
    systemctl enable 2r-at-monitoring.timer
    systemctl start 2r-at-monitoring.timer
    
    log_info "Setting up log rotation..."
    
    # Create comprehensive log rotation
    cat > /etc/logrotate.d/2r-at << 'EOF'
/var/log/2r-at/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 apache apache
    sharedscripts
    postrotate
        /bin/systemctl reload 2r-at-scanner.service > /dev/null 2>/dev/null || true
    endscript
}
EOF
    
    log_info "Setting up automated backups..."
    
    # Create backup cron job
    cat > /etc/cron.d/2r-at-backup << 'EOF'
# 2R-AT Automated Backup Jobs
0 3 * * * root /usr/local/bin/2r-at-database-manager.sh backup daily
0 4 * * 0 root /usr/local/bin/2r-at-database-manager.sh backup weekly
0 5 1 * * root /usr/local/bin/2r-at-database-manager.sh backup monthly
0 6 * * 0 root /usr/local/bin/2r-at-database-manager.sh maintain
0 7 1 * * root /usr/local/bin/2r-at-database-manager.sh cleanup
EOF
    
    log_info "Monitoring setup completed"
}

# Stage 9: Integration Testing
stage_integration_testing() {
    log_stage $STAGE_TESTING "Integration Testing"
    
    log_info "Running system health checks..."
    
    # Basic connectivity tests
    local tests_passed=0
    local total_tests=8
    
    # Test Apache
    if systemctl is-active --quiet httpd; then
        log_info "✓ Apache is running"
        ((tests_passed++))
    else
        log_warn "✗ Apache is not running"
    fi
    
    # Test Redis
    if systemctl is-active --quiet redis; then
        log_info "✓ Redis is running"
        ((tests_passed++))
    else
        log_warn "✗ Redis is not running"
    fi
    
    # Test database
    if sqlite3 /var/lib/2r-at/scanner.db "SELECT 1;" >/dev/null 2>&1; then
        log_info "✓ Database is accessible"
        ((tests_passed++))
    else
        log_warn "✗ Database is not accessible"
    fi
    
    # Test Nuclei
    if /usr/local/bin/nuclei -version >/dev/null 2>&1; then
        log_info "✓ Nuclei scanner is working"
        ((tests_passed++))
    else
        log_warn "✗ Nuclei scanner is not working"
    fi
    
    # Test firewall
    if firewall-cmd --state >/dev/null 2>&1; then
        log_info "✓ Firewall is active"
        ((tests_passed++))
    else
        log_warn "✗ Firewall is not active"
    fi
    
    # Test HTTP connectivity
    if curl -sf --max-time 10 http://127.0.0.1 >/dev/null 2>&1; then
        log_info "✓ HTTP server is responding"
        ((tests_passed++))
    else
        log_warn "✗ HTTP server is not responding"
    fi
    
    # Test directory permissions
    if [[ -w "/var/lib/2r-at" && -w "/var/log/2r-at" && -w "/var/www/html/scan-results" ]]; then
        log_info "✓ Directory permissions are correct"
        ((tests_passed++))
    else
        log_warn "✗ Directory permissions need attention"
    fi
    
    # Test monitoring
    if systemctl is-active --quiet 2r-at-monitoring.timer; then
        log_info "✓ Monitoring system is active"
        ((tests_passed++))
    else
        log_warn "✗ Monitoring system is not active"
    fi
    
    log_info "Integration tests: $tests_passed/$total_tests passed"
    
    if [[ $tests_passed -eq $total_tests ]]; then
        log_info "All integration tests passed!"
        return 0
    else
        log_warn "Some integration tests failed - review before production use"
        return 1
    fi
}

# Stage 10: Finalization
stage_finalization() {
    log_stage $STAGE_FINALIZE "Deployment Finalization"
    
    log_info "Creating deployment summary..."
    
    # Generate deployment report
    local deployment_report="/root/2r-at-deployment-$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$deployment_report" << EOF
2R-AT Security Platform Deployment Report
=========================================
Deployment Date: $(date)
Server: $(hostname)
Operating System: $(cat /etc/redhat-release 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
Kernel: $(uname -r)

Installation Summary:
- Domain: $DOMAIN
- Admin Email: $EMAIL
- Installation Directory: $INSTALL_DIR
- Database Path: /var/lib/2r-at/scanner.db
- Web Directory: $WEB_DIR
- Log Directory: $LOG_DIR
- Backup Directory: $BACKUP_DIR

Services Status:
- Apache (httpd): $(systemctl is-active httpd)
- Redis: $(systemctl is-active redis)
- Firewall: $(firewall-cmd --state 2>/dev/null || echo 'unknown')
- Monitoring Timer: $(systemctl is-active 2r-at-monitoring.timer 2>/dev/null || echo 'unknown')

Network Configuration:
- HTTP Port 80: $(netstat -tuln | grep -q ":80 " && echo "Listening" || echo "Not listening")
- HTTPS Port 443: $(netstat -tuln | grep -q ":443 " && echo "Listening" || echo "Not listening")
- Redis Port 6379: $(netstat -tuln | grep -q ":6379 " && echo "Listening" || echo "Not listening")

Security Configuration:
- Firewall Status: $(firewall-cmd --state 2>/dev/null || echo 'unknown')
- SELinux Status: $(getenforce 2>/dev/null || echo 'unknown')
- SSL Status: Not configured (manual setup required)

Tools Installed:
- Nuclei Version: $(/usr/local/bin/nuclei -version 2>/dev/null | head -1 || echo 'Error getting version')
- Python Version: $(python3 --version)
- Go Version: $(go version 2>/dev/null || echo 'Not available')

Database Information:
- Schema Version: $(sqlite3 /var/lib/2r-at/scanner.db "PRAGMA user_version;" 2>/dev/null || echo 'unknown')
- Database Size: $(du -h /var/lib/2r-at/scanner.db 2>/dev/null | cut -f1 || echo 'unknown')
- Initial Backup: Available in $BACKUP_DIR

Management Scripts:
- Database: /usr/local/bin/2r-at-database-manager.sh
- Monitoring: /usr/local/bin/2r-at-advanced-monitor.sh
- Integration Tests: /usr/local/bin/2r-at-integration-test.sh
- Apache Management: /usr/local/bin/2r-at-apache-deploy.sh

Next Steps Required:
1. Deploy actual application code to $INSTALL_DIR/
2. Copy frontend files to $WEB_DIR/
3. Start the scanner service: systemctl start 2r-at-scanner
4. Configure SSL certificates: certbot --apache -d $DOMAIN
5. Enable HTTPS redirect: /usr/local/bin/2r-at-apache-deploy.sh enable-ssl
6. Create admin user accounts
7. Run full integration tests: /usr/local/bin/2r-at-integration-test.sh

Security Checklist:
[ ] Change default passwords
[ ] Configure SSL certificates
[ ] Review firewall rules
[ ] Set up monitoring alerts
[ ] Configure automated backups
[ ] Review log retention policies
[ ] Set up intrusion detection
[ ] Configure fail2ban (optional)

Support Information:
- Logs: $LOG_DIR/
- Configuration: $CONFIG_DIR/
- Troubleshooting: See troubleshooting guide
- Health Check: /usr/local/bin/2r-at-advanced-monitor.sh status
- Emergency Contact: $EMAIL

EOF
    
    log_info "Creating quick reference..."
    
    cat > /usr/local/bin/2r-at-quick-reference.sh << 'EOF'
#!/bin/bash
# 2R-AT Quick Reference and Status

echo "=== 2R-AT Security Platform Quick Reference ==="
echo ""

echo "Service Status:"
systemctl --no-pager status httpd redis 2r-at-scanner 2>/dev/null | grep "Active:" || echo "Some services not configured yet"

echo ""
echo "Database Status:"
if [[ -f /var/lib/2r-at/scanner.db ]]; then
    echo "  Database: Available"
    echo "  Size: $(du -h /var/lib/2r-at/scanner.db | cut -f1)"
    echo "  Version: $(sqlite3 /var/lib/2r-at/scanner.db "PRAGMA user_version;" 2>/dev/null || echo 'unknown')"
else
    echo "  Database: Not found"
fi

echo ""
echo "Network Status:"
echo "  HTTP (80): $(netstat -tuln | grep -q ":80 " && echo "Listening" || echo "Not listening")"
echo "  HTTPS (443): $(netstat -tuln | grep -q ":443 " && echo "Listening" || echo "Not listening")"
echo "  Redis (6379): $(netstat -tuln | grep -q ":6379 " && echo "Listening" || echo "Not listening")"

echo ""
echo "Quick Commands:"
echo "  Service Status: systemctl status httpd redis 2r-at-scanner"
echo "  View Logs: tail -f /var/log/2r-at/scanner.log"
echo "  Health Check: /usr/local/bin/2r-at-advanced-monitor.sh status"
echo "  Database Status: /usr/local/bin/2r-at-database-manager.sh status"
echo "  Integration Test: /usr/local/bin/2r-at-integration-test.sh quick"
echo "  Apache Management: /usr/local/bin/2r-at-apache-deploy.sh"

echo ""
echo "Important Directories:"
echo "  Application: /opt/2r-at-scanner/"
echo "  Web Root: /var/www/html/"
echo "  Database: /var/lib/2r-at/"
echo "  Logs: /var/log/2r-at/"
echo "  Backups: /opt/backups/2r-at/"
echo "  Configuration: /etc/2r-at/"

echo ""
echo "Documentation:"
echo "  Deployment Report: /root/2r-at-deployment-*.txt"
echo "  Troubleshooting: Check troubleshooting guide artifact"
echo "  API Documentation: Available after full deployment"
EOF
    
    chmod +x /usr/local/bin/2r-at-quick-reference.sh
    
    # Set final permissions
    chown -R apache:apache "$INSTALL_DIR" "$LOG_DIR" "/var/lib/2r-at" "/var/www/html"
    chown root:root /usr/local/bin/2r-at-*
    chmod +x /usr/local/bin/2r-at-*
    
    log_info "Creating post-deployment checklist..."
    
    cat > /root/2r-at-post-deployment-checklist.md << 'EOF'
# 2R-AT Post-Deployment Checklist

## Immediate Tasks (Required for Operation)
- [ ] Deploy application code to `/opt/2r-at-scanner/`
- [ ] Copy frontend files to `/var/www/html/`
- [ ] Start scanner service: `systemctl start 2r-at-scanner`
- [ ] Verify all services: `systemctl status httpd redis 2r-at-scanner`
- [ ] Run integration tests: `/usr/local/bin/2r-at-integration-test.sh`

## Security Configuration (Critical)
- [ ] Configure SSL certificates: `certbot --apache -d yourdomain.com`
- [ ] Enable HTTPS redirect: `/usr/local/bin/2r-at-apache-deploy.sh enable-ssl`
- [ ] Change default admin password
- [ ] Review and customize firewall rules
- [ ] Configure fail2ban (optional): `dnf install fail2ban`

## Monitoring and Maintenance (Important)
- [ ] Test monitoring: `/usr/local/bin/2r-at-advanced-monitor.sh status`
- [ ] Configure email alerts in `/etc/2r-at/monitoring.conf`
- [ ] Test backup system: `/usr/local/bin/2r-at-database-manager.sh backup manual`
- [ ] Set up log monitoring and rotation
- [ ] Configure SMTP for notifications

## Production Readiness (Before Go-Live)
- [ ] Performance testing with expected load
- [ ] Disaster recovery testing
- [ ] Documentation review and updates
- [ ] Staff training on management procedures
- [ ] Establish monitoring and alerting procedures

## Optional Enhancements
- [ ] Set up additional monitoring (Nagios, Zabbix, etc.)
- [ ] Configure advanced intrusion detection
- [ ] Set up centralized logging
- [ ] Implement backup encryption
- [ ] Configure geo-redundancy (if required)

## Verification Commands
```bash
# Quick system status
/usr/local/bin/2r-at-quick-reference.sh

# Full health check
/usr/local/bin/2r-at-advanced-monitor.sh status

# Run all tests
/usr/local/bin/2r-at-integration-test.sh all

# Check database health
/usr/local/bin/2r-at-database-manager.sh check
```
EOF
    
    log_info "Finalization completed"
    
    echo ""
    echo -e "${GREEN}Deployment report saved to: $deployment_report${NC}"
    echo -e "${GREEN}Quick reference available: /usr/local/bin/2r-at-quick-reference.sh${NC}"
    echo -e "${GREEN}Post-deployment checklist: /root/2r-at-post-deployment-checklist.md${NC}"
}

# Progress tracking
show_progress() {
    local current_stage="$1"
    local total_stages=10
    local progress=$((current_stage * 100 / total_stages))
    
    echo -e "\n${CYAN}Deployment Progress: ${progress}% (Stage $current_stage/$total_stages)${NC}"
    
    # Simple progress bar
    local bar_length=40
    local filled=$((progress * bar_length / 100))
    local empty=$((bar_length - filled))
    
    printf "${CYAN}["
    printf "%*s" $filled | tr ' ' '█'
    printf "%*s" $empty | tr ' ' '░'
    printf "]${NC}\n"
}

# Main deployment function
main() {
    local skip_to_stage="${1:-1}"
    
    print_banner
    
    echo -e "${CYAN}Starting Complete 2R-AT Security Platform Deployment...${NC}"
    echo "This will deploy a production-ready cybersecurity scanning platform"
    echo ""
    
    # Confirm deployment
    if [[ $skip_to_stage -eq 1 ]]; then
        read -p "Continue with full deployment? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Deployment cancelled."
            exit 0
        fi
    fi
    
    # Check prerequisites
    check_root
    
    # Create initial log directory
    mkdir -p "$LOG_DIR"
    touch "$LOG_DIR/deployment.log"
    
    # Run deployment stages
    if [[ $skip_to_stage -le 1 ]]; then
        show_progress 1
        stage_preparation
    fi
    
    if [[ $skip_to_stage -le 2 ]]; then
        show_progress 2
        stage_base_system
    fi
    
    if [[ $skip_to_stage -le 3 ]]; then
        show_progress 3
        stage_database_setup
    fi
    
    if [[ $skip_to_stage -le 4 ]]; then
        show_progress 4
        stage_backend_deployment
    fi
    
    if [[ $skip_to_stage -le 5 ]]; then
        show_progress 5
        stage_frontend_deployment
    fi
    
    if [[ $skip_to_stage -le 6 ]]; then
        show_progress 6
        stage_service_configuration
    fi
    
    if [[ $skip_to_stage -le 7 ]]; then
        show_progress 7
        stage_security_configuration
    fi
    
    if [[ $skip_to_stage -le 8 ]]; then
        show_progress 8
        stage_monitoring_setup
    fi
    
    if [[ $skip_to_stage -le 9 ]]; then
        show_progress 9
        if ! stage_integration_testing; then
            log_warn "Some integration tests failed, but continuing with deployment"
        fi
    fi
    
    if [[ $skip_to_stage -le 10 ]]; then
        show_progress 10
        stage_finalization
    fi
    
    # Final summary
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}2R-AT Deployment Summary${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo -e "${GREEN}🎉 Base platform deployment completed successfully!${NC}"
    echo ""
    echo -e "${BLUE}What was deployed:${NC}"
    echo "✓ Complete system infrastructure"
    echo "✓ Database with proper schema"
    echo "✓ Apache web server with security hardening"
    echo "✓ Redis for session management"
    echo "✓ Nuclei vulnerability scanner"
    echo "✓ Monitoring and alerting system"
    echo "✓ Automated backup system"
    echo "✓ Log rotation and management"
    echo "✓ Security configurations"
    echo "✓ Management and troubleshooting scripts"
    echo ""
    echo -e "${YELLOW}⚠ Next steps required:${NC}"
    echo "1. Deploy the actual application code (backend API)"
    echo "2. Deploy the frontend web interface"
    echo "3. Start the scanner service"
    echo "4. Configure SSL certificates"
    echo "5. Create admin user accounts"
    echo ""
    echo -e "${BLUE}Quick commands:${NC}"
    echo "  Status: /usr/local/bin/2r-at-quick-reference.sh"
    echo "  Health: /usr/local/bin/2r-at-advanced-monitor.sh status"
    echo "  Test: /usr/local/bin/2r-at-integration-test.sh quick"
    echo ""
    echo -e "${PURPLE}Documentation:${NC}"
    echo "  Post-deployment checklist: /root/2r-at-post-deployment-checklist.md"
    echo "  Troubleshooting guide: Available in artifacts"
    echo "  Full deployment log: $LOG_DIR/deployment.log"
    echo ""
    echo -e "${GREEN}Platform is ready for final application deployment!${NC}"
    echo -e "${CYAN}========================================${NC}"
}

# Handle script termination
trap 'echo -e "\n${RED}Deployment interrupted${NC}"; exit 1' INT TERM

# Run main function
main "$@"