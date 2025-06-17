#!/bin/bash
# ========================================
# 2R-AT Apache Configuration Script
# Complete Apache setup for the 2R-AT platform
# ========================================

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_step() {
    echo -e "\n${BLUE}===${NC} $1 ${BLUE}===${NC}"
}

# Create main virtual host configuration
create_main_vhost() {
    print_step "Creating Main Virtual Host Configuration"
    
    cat > /etc/httpd/conf.d/2r-at.conf << 'EOF'
# ========================================
# 2R-AT Security Platform Apache Configuration
# ========================================

# Security Headers Module (load if available)
LoadModule headers_module modules/mod_headers.so
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule ssl_module modules/mod_ssl.so
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so

# Hide Apache version
ServerTokens Prod
ServerSignature Off

# Main Virtual Host (HTTP)
<VirtualHost *:80>
    ServerName 2r-at.com
    ServerAlias www.2r-at.com localhost
    DocumentRoot /var/www/html
    
    # Logging
    LogLevel warn
    ErrorLog /var/log/httpd/2r-at_error.log
    CustomLog /var/log/httpd/2r-at_access.log combined
    
    # Security Headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self';"
    
    # Remove server info
    Header unset Server
    Header always unset X-Powered-By
    
    # HTTPS Redirect (uncomment when SSL is configured)
    # RewriteEngine On
    # RewriteCond %{HTTPS} off
    # RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
    
    # API Proxy Configuration
    ProxyPreserveHost On
    ProxyRequests Off
    
    # API endpoints proxy to Flask backend
    ProxyPass /api/ http://127.0.0.1:5000/api/
    ProxyPassReverse /api/ http://127.0.0.1:5000/api/
    
    # Set headers for backend
    ProxyPassReverse /api/ http://127.0.0.1:5000/api/
    <Location "/api/">
        ProxyPassReverse /
        RequestHeader set X-Forwarded-Proto "http"
        RequestHeader set X-Forwarded-Port "80"
    </Location>
    
    # Static file handling
    <Directory "/var/www/html">
        Options -Indexes -FollowSymLinks
        AllowOverride None
        Require all granted
        
        # Cache static assets
        <FilesMatch "\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$">
            ExpiresActive On
            ExpiresDefault "access plus 1 month"
            Header append Cache-Control "public, immutable"
        </FilesMatch>
        
        # No cache for HTML
        <FilesMatch "\.(html|htm)$">
            ExpiresActive On
            ExpiresDefault "access plus 0 seconds"
            Header set Cache-Control "no-cache, no-store, must-revalidate"
            Header set Pragma "no-cache"
        </FilesMatch>
    </Directory>
    
    # Scan results directory
    <Directory "/var/www/html/scan-results">
        Options -Indexes -FollowSymLinks
        AllowOverride None
        Require all granted
        
        # Only allow authenticated access (handled by application)
        <FilesMatch "\.(html|json|txt)$">
            Header set Cache-Control "private, no-cache"
        </FilesMatch>
    </Directory>
    
    # Security - Block access to sensitive files
    <FilesMatch "\.(htaccess|htpasswd|ini|log|sh|inc|bak|conf|config)$">
        Require all denied
    </FilesMatch>
    
    # Block access to hidden files
    <FilesMatch "^\.">
        Require all denied
    </FilesMatch>
    
    # Block access to backup files
    <FilesMatch "\~$">
        Require all denied
    </FilesMatch>
    
    # Error pages
    ErrorDocument 404 /404.html
    ErrorDocument 500 /500.html
    ErrorDocument 503 /503.html
</VirtualHost>

# HTTPS Virtual Host (SSL)
<VirtualHost *:443>
    ServerName 2r-at.com
    ServerAlias www.2r-at.com
    DocumentRoot /var/www/html
    
    # SSL Configuration
    SSLEngine on
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder off
    SSLSessionTickets off
    
    # SSL Certificate files (update paths as needed)
    # For Let's Encrypt:
    SSLCertificateFile /etc/letsencrypt/live/2r-at.com/cert.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/2r-at.com/privkey.pem
    SSLCertificateChainFile /etc/letsencrypt/live/2r-at.com/chain.pem
    
    # For self-signed (development):
    # SSLCertificateFile /etc/ssl/certs/2r-at.crt
    # SSLCertificateKeyFile /etc/ssl/private/2r-at.key
    
    # Logging
    LogLevel warn
    ErrorLog /var/log/httpd/2r-at_ssl_error.log
    CustomLog /var/log/httpd/2r-at_ssl_access.log combined
    
    # Enhanced Security Headers for HTTPS
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self'; upgrade-insecure-requests"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()"
    
    # Remove server info
    Header unset Server
    Header always unset X-Powered-By
    
    # API Proxy Configuration (same as HTTP but with HTTPS headers)
    ProxyPreserveHost On
    ProxyRequests Off
    
    ProxyPass /api/ http://127.0.0.1:5000/api/
    ProxyPassReverse /api/ http://127.0.0.1:5000/api/
    
    <Location "/api/">
        ProxyPassReverse /
        RequestHeader set X-Forwarded-Proto "https"
        RequestHeader set X-Forwarded-Port "443"
        RequestHeader set X-Forwarded-SSL "on"
    </Location>
    
    # Same directory configurations as HTTP
    <Directory "/var/www/html">
        Options -Indexes -FollowSymLinks
        AllowOverride None
        Require all granted
        
        <FilesMatch "\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$">
            ExpiresActive On
            ExpiresDefault "access plus 1 month"
            Header append Cache-Control "public, immutable"
        </FilesMatch>
        
        <FilesMatch "\.(html|htm)$">
            ExpiresActive On
            ExpiresDefault "access plus 0 seconds"
            Header set Cache-Control "no-cache, no-store, must-revalidate"
            Header set Pragma "no-cache"
        </FilesMatch>
    </Directory>
    
    <Directory "/var/www/html/scan-results">
        Options -Indexes -FollowSymLinks
        AllowOverride None
        Require all granted
        
        <FilesMatch "\.(html|json|txt)$">
            Header set Cache-Control "private, no-cache"
        </FilesMatch>
    </Directory>
    
    # Security restrictions (same as HTTP)
    <FilesMatch "\.(htaccess|htpasswd|ini|log|sh|inc|bak|conf|config)$">
        Require all denied
    </FilesMatch>
    
    <FilesMatch "^\.">
        Require all denied
    </FilesMatch>
    
    <FilesMatch "\~$">
        Require all denied
    </FilesMatch>
    
    # Error pages
    ErrorDocument 404 /404.html
    ErrorDocument 500 /500.html
    ErrorDocument 503 /503.html
</VirtualHost>

# Additional Security Configuration
<IfModule mod_evasive24.c>
    DOSHashTableSize    512
    DOSPageCount        3
    DOSPageInterval     1
    DOSSiteCount        50
    DOSSiteInterval     1
    DOSBlockingPeriod   600
</IfModule>

# Compression (if mod_deflate is available)
<IfModule mod_deflate.c>
    SetOutputFilter DEFLATE
    SetEnvIfNoCase Request_URI \
        \.(?:gif|jpe?g|png)$ no-gzip dont-vary
    SetEnvIfNoCase Request_URI \
        \.(?:exe|t?gz|zip|bz2|sit|rar)$ no-gzip dont-vary
    SetEnvIfNoCase Request_URI \
        \.pdf$ no-gzip dont-vary
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/html
    AddOutputFilterByType DEFLATE text/xml
    AddOutputFilterByType DEFLATE text/css
    AddOutputFilterByType DEFLATE application/xml
    AddOutputFilterByType DEFLATE application/xhtml+xml
    AddOutputFilterByType DEFLATE application/rss+xml
    AddOutputFilterByType DEFLATE application/javascript
    AddOutputFilterByType DEFLATE application/x-javascript
    AddOutputFilterByType DEFLATE application/json
</IfModule>

# Rate limiting (if mod_evasive is not available, use basic rate limiting)
<IfModule !mod_evasive24.c>
    <Location "/api/">
        # Basic rate limiting using mod_rewrite
        RewriteEngine On
        RewriteMap throttle "prg:/usr/local/bin/throttle.pl"
        RewriteCond %{REQUEST_URI} ^/api/
        RewriteCond ${throttle:%{REMOTE_ADDR}} ^THROTTLED
        RewriteRule ^(.*)$ - [R=429,L]
    </Location>
</IfModule>
EOF

    print_status "Main virtual host configuration created"
}

# Create error pages
create_error_pages() {
    print_step "Creating Custom Error Pages"
    
    # 404 Error Page
    cat > /var/www/html/404.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Page Not Found | 2R-AT Security</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1f2937 0%, #111827 100%);
            color: #f9fafb;
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .error-container {
            text-align: center;
            max-width: 600px;
            padding: 2rem;
        }
        .error-code {
            font-size: 8rem;
            font-weight: bold;
            color: #1a73e8;
            margin-bottom: 1rem;
        }
        .error-message {
            font-size: 1.5rem;
            margin-bottom: 2rem;
            color: #d1d5db;
        }
        .error-description {
            margin-bottom: 2rem;
            color: #9ca3af;
        }
        .home-link {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            background: linear-gradient(45deg, #1a73e8, #4285f4);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            transition: transform 0.3s ease;
        }
        .home-link:hover {
            transform: translateY(-2px);
        }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-code">404</div>
        <h1 class="error-message">Page Not Found</h1>
        <p class="error-description">
            The page you're looking for doesn't exist or has been moved.
        </p>
        <a href="/" class="home-link">Return to Dashboard</a>
    </div>
</body>
</html>
EOF

    # 500 Error Page
    cat > /var/www/html/500.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>500 - Server Error | 2R-AT Security</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1f2937 0%, #111827 100%);
            color: #f9fafb;
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .error-container {
            text-align: center;
            max-width: 600px;
            padding: 2rem;
        }
        .error-code {
            font-size: 8rem;
            font-weight: bold;
            color: #ea4335;
            margin-bottom: 1rem;
        }
        .error-message {
            font-size: 1.5rem;
            margin-bottom: 2rem;
            color: #d1d5db;
        }
        .error-description {
            margin-bottom: 2rem;
            color: #9ca3af;
        }
        .home-link {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            background: linear-gradient(45deg, #1a73e8, #4285f4);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            transition: transform 0.3s ease;
            margin-right: 1rem;
        }
        .home-link:hover {
            transform: translateY(-2px);
        }
        .support-link {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            background: transparent;
            color: #9ca3af;
            text-decoration: none;
            border: 1px solid #374151;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        .support-link:hover {
            background: #374151;
            color: #f9fafb;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-code">500</div>
        <h1 class="error-message">Server Error</h1>
        <p class="error-description">
            We're experiencing technical difficulties. Our team has been notified and is working to resolve the issue.
        </p>
        <a href="/" class="home-link">Return to Dashboard</a>
        <a href="mailto:admin@2r-at.com" class="support-link">Contact Support</a>
    </div>
</body>
</html>
EOF

    # 503 Service Unavailable Page
    cat > /var/www/html/503.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>503 - Service Unavailable | 2R-AT Security</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1f2937 0%, #111827 100%);
            color: #f9fafb;
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .error-container {
            text-align: center;
            max-width: 600px;
            padding: 2rem;
        }
        .error-code {
            font-size: 8rem;
            font-weight: bold;
            color: #fbbc04;
            margin-bottom: 1rem;
        }
        .error-message {
            font-size: 1.5rem;
            margin-bottom: 2rem;
            color: #d1d5db;
        }
        .error-description {
            margin-bottom: 2rem;
            color: #9ca3af;
        }
        .retry-button {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            background: linear-gradient(45deg, #1a73e8, #4285f4);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            transition: transform 0.3s ease;
            cursor: pointer;
            border: none;
        }
        .retry-button:hover {
            transform: translateY(-2px);
        }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-code">503</div>
        <h1 class="error-message">Service Unavailable</h1>
        <p class="error-description">
            The service is temporarily unavailable due to maintenance or high load. Please try again in a few moments.
        </p>
        <button onclick="window.location.reload()" class="retry-button">Try Again</button>
    </div>
</body>
</html>
EOF

    print_status "Custom error pages created"
}

# Create additional security configuration
create_security_config() {
    print_step "Creating Additional Security Configuration"
    
    cat > /etc/httpd/conf.d/2r-at-security.conf << 'EOF'
# ========================================
# 2R-AT Additional Security Configuration
# ========================================

# Hide sensitive server information
ServerTokens Prod
ServerSignature Off

# Prevent access to .htaccess and other sensitive files
<Files ~ "^\.ht">
    Require all denied
</Files>

# Prevent access to backup files
<FilesMatch "\.(bak|backup|swp|tmp|log)$">
    Require all denied
</FilesMatch>

# Prevent execution of scripts in upload directories
<Directory "/var/www/html/scan-results">
    Options -ExecCGI
    RemoveHandler .php .phtml .php3 .php4 .php5 .pl .py .cgi .sh
    RemoveType application/x-httpd-php
    php_flag engine off
    SetHandler default-handler
</Directory>

# Clickjacking protection
Header always append X-Frame-Options DENY

# MIME type sniffing protection
Header always set X-Content-Type-Options nosniff

# XSS protection
Header always set X-XSS-Protection "1; mode=block"

# Remove ETags (for security)
FileETag None

# Timeout settings
Timeout 60
KeepAliveTimeout 15

# Request size limits
LimitRequestBody 10485760  # 10MB max request size
LimitRequestFields 100
LimitRequestFieldSize 1024
LimitRequestLine 4096

# Connection limits
<IfModule mod_reqtimeout.c>
    RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500
</IfModule>

# Disable server-status and server-info
<Location "/server-status">
    Require all denied
</Location>

<Location "/server-info">
    Require all denied
</Location>

# Disable TRACE method
TraceEnable off

# Log format for security monitoring
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\" %D" security_combined
EOF

    print_status "Additional security configuration created"
}

# Create SSL configuration
create_ssl_config() {
    print_step "Creating SSL Configuration"
    
    cat > /etc/httpd/conf.d/2r-at-ssl.conf << 'EOF'
# ========================================
# 2R-AT SSL/TLS Configuration
# ========================================

# Load SSL module
LoadModule ssl_module modules/mod_ssl.so

# Global SSL configuration
SSLRandomSeed startup builtin
SSLRandomSeed connect builtin

# SSL Session Cache
SSLSessionCache shmcb:/var/cache/mod_ssl/scache(512000)
SSLSessionCacheTimeout 300

# SSL Protocol and Cipher Configuration
SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder off

# SSL Options
SSLOptions +FakeBasicAuth +ExportCertData +StrictRequire
SSLSessionTickets off

# OCSP Stapling
SSLUseStapling on
SSLStaplingCache shmcb:/var/cache/mod_ssl/stapling(32768)
SSLStaplingStandardCacheTimeout 3600
SSLStaplingErrorCacheTimeout 600

# Security headers for SSL
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
EOF

    print_status "SSL configuration created"
}

# Create log rotation configuration
create_logrotate_config() {
    print_step "Creating Log Rotation Configuration"
    
    cat > /etc/logrotate.d/2r-at-apache << 'EOF'
/var/log/httpd/2r-at_*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 640 apache apache
    sharedscripts
    postrotate
        /bin/systemctl reload httpd.service > /dev/null 2>/dev/null || true
    endscript
}
EOF

    print_status "Log rotation configuration created"
}

# Create maintenance page
create_maintenance_page() {
    print_step "Creating Maintenance Page"
    
    cat > /var/www/html/maintenance.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Maintenance Mode | 2R-AT Security</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1f2937 0%, #111827 100%);
            color: #f9fafb;
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .maintenance-container {
            text-align: center;
            max-width: 600px;
            padding: 2rem;
        }
        .logo {
            font-size: 3rem;
            color: #1a73e8;
            margin-bottom: 2rem;
        }
        .maintenance-title {
            font-size: 2rem;
            margin-bottom: 1rem;
            color: #d1d5db;
        }
        .maintenance-message {
            font-size: 1.1rem;
            margin-bottom: 2rem;
            color: #9ca3af;
            line-height: 1.6;
        }
        .progress-bar {
            width: 100%;
            height: 4px;
            background: #374151;
            border-radius: 2px;
            overflow: hidden;
            margin: 2rem 0;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #1a73e8, #4285f4);
            width: 0%;
            animation: progress 10s ease-in-out infinite;
        }
        @keyframes progress {
            0%, 100% { width: 0%; }
            50% { width: 100%; }
        }
        .eta {
            color: #6b7280;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="maintenance-container">
        <div class="logo">🛠️ 2R-AT</div>
        <h1 class="maintenance-title">System Maintenance</h1>
        <p class="maintenance-message">
            We're currently performing scheduled maintenance to improve your experience. 
            The platform will be back online shortly.
        </p>
        <div class="progress-bar">
            <div class="progress-fill"></div>
        </div>
        <p class="eta">
            Estimated completion: Within the next hour<br>
            Thank you for your patience.
        </p>
    </div>
</body>
</html>
EOF

    print_status "Maintenance page created"
}

# Setup directory permissions
setup_permissions() {
    print_step "Setting Up Directory Permissions"
    
    # Create necessary directories
    mkdir -p /var/www/html/scan-results
    mkdir -p /var/log/httpd
    mkdir -p /var/cache/mod_ssl
    
    # Set ownership
    chown -R apache:apache /var/www/html
    chown apache:apache /var/log/httpd
    chown apache:apache /var/cache/mod_ssl
    
    # Set permissions
    chmod 755 /var/www/html
    chmod 755 /var/www/html/scan-results
    chmod 644 /var/www/html/*.html
    chmod 755 /var/log/httpd
    chmod 700 /var/cache/mod_ssl
    
    # SELinux contexts
    if command -v restorecon >/dev/null 2>&1; then
        restorecon -Rv /var/www/html
        restorecon -Rv /var/log/httpd
        setsebool -P httpd_can_network_connect 1
    fi
    
    print_status "Directory permissions configured"
}

# Test Apache configuration
test_apache_config() {
    print_step "Testing Apache Configuration"
    
    # Test configuration syntax
    if httpd -t; then
        print_status "Apache configuration syntax is valid"
    else
        echo -e "${YELLOW}[WARNING]${NC} Apache configuration has syntax errors"
        return 1
    fi
    
    # Test virtual host configuration
    httpd -S
    
    print_status "Apache configuration test completed"
}

# Create deployment script
create_deployment_script() {
    print_step "Creating Apache Deployment Script"
    
    cat > /usr/local/bin/2r-at-apache-deploy.sh << 'EOF'
#!/bin/bash
# 2R-AT Apache Deployment and Management Script

case "${1:-help}" in
    "deploy")
        echo "Deploying Apache configuration..."
        systemctl reload httpd
        echo "Apache configuration deployed"
        ;;
    "enable-ssl")
        echo "Enabling SSL configuration..."
        # Uncomment HTTPS redirect in main config
        sed -i 's/# RewriteEngine On/RewriteEngine On/' /etc/httpd/conf.d/2r-at.conf
        sed -i 's/# RewriteCond %{HTTPS} off/RewriteCond %{HTTPS} off/' /etc/httpd/conf.d/2r-at.conf
        sed -i 's/# RewriteRule \^(.*)\$ https/RewriteRule ^(.*)$ https/' /etc/httpd/conf.d/2r-at.conf
        systemctl reload httpd
        echo "SSL redirect enabled"
        ;;
    "disable-ssl")
        echo "Disabling SSL redirect..."
        sed -i 's/RewriteEngine On/# RewriteEngine On/' /etc/httpd/conf.d/2r-at.conf
        sed -i 's/RewriteCond %{HTTPS} off/# RewriteCond %{HTTPS} off/' /etc/httpd/conf.d/2r-at.conf
        sed -i 's/RewriteRule \^(.*)\$ https/# RewriteRule ^(.*)$ https/' /etc/httpd/conf.d/2r-at.conf
        systemctl reload httpd
        echo "SSL redirect disabled"
        ;;
    "maintenance-on")
        echo "Enabling maintenance mode..."
        mv /var/www/html/index.html /var/www/html/index.html.bak 2>/dev/null || true
        cp /var/www/html/maintenance.html /var/www/html/index.html
        echo "Maintenance mode enabled"
        ;;
    "maintenance-off")
        echo "Disabling maintenance mode..."
        if [[ -f /var/www/html/index.html.bak ]]; then
            mv /var/www/html/index.html.bak /var/www/html/index.html
        fi
        echo "Maintenance mode disabled"
        ;;
    "test")
        echo "Testing Apache configuration..."
        httpd -t && echo "Configuration OK" || echo "Configuration has errors"
        ;;
    "reload")
        echo "Reloading Apache configuration..."
        systemctl reload httpd
        echo "Apache reloaded"
        ;;
    "status")
        systemctl status httpd
        ;;
    "logs")
        tail -f /var/log/httpd/2r-at_*.log
        ;;
    *)
        echo "2R-AT Apache Management Script"
        echo ""
        echo "Usage: $0 [COMMAND]"
        echo ""
        echo "Commands:"
        echo "  deploy          Deploy Apache configuration"
        echo "  enable-ssl      Enable HTTPS redirect"
        echo "  disable-ssl     Disable HTTPS redirect" 
        echo "  maintenance-on  Enable maintenance mode"
        echo "  maintenance-off Disable maintenance mode"
        echo "  test           Test Apache configuration"
        echo "  reload         Reload Apache configuration"
        echo "  status         Show Apache status"
        echo "  logs           Show real-time logs"
        echo ""
        ;;
esac
EOF

    chmod +x /usr/local/bin/2r-at-apache-deploy.sh
    print_status "Apache deployment script created"
}

# Main execution
main() {
    print_step "Configuring Apache for 2R-AT Security Platform"
    
    # Create all configuration files
    create_main_vhost
    create_error_pages
    create_security_config
    create_ssl_config
    create_logrotate_config
    create_maintenance_page
    create_deployment_script
    
    # Setup permissions
    setup_permissions
    
    # Test configuration
    if test_apache_config; then
        print_step "Apache Configuration Complete"
        echo ""
        echo -e "${GREEN}✓ Apache configured successfully for 2R-AT platform${NC}"
        echo ""
        echo "Next steps:"
        echo "1. Deploy frontend files to /var/www/html/"
        echo "2. Configure SSL certificates:"
        echo "   certbot --apache -d yourdomain.com"
        echo "3. Enable SSL redirect:"
        echo "   /usr/local/bin/2r-at-apache-deploy.sh enable-ssl"
        echo "4. Restart Apache:"
        echo "   systemctl restart httpd"
        echo ""
        echo "Management commands:"
        echo "  /usr/local/bin/2r-at-apache-deploy.sh [command]"
        echo ""
    else
        echo -e "${YELLOW}[WARNING]${NC} Apache configuration has issues. Please review and fix before proceeding."
        return 1
    fi
}

# Run main function
main "$@"