#!/bin/bash
# ========================================
# 2R-AT Systemd Service Configuration
# Service files and startup scripts
# ========================================

# Create the main systemd service file
cat > /etc/systemd/system/2r-at-scanner.service << 'EOF'
[Unit]
Description=2R-AT Security Platform - Scanner API Service
Documentation=https://2r-at.com/docs
After=network.target redis.service
Wants=redis.service
PartOf=2r-at.target

[Service]
Type=forking
User=apache
Group=apache
WorkingDirectory=/opt/2r-at-scanner
Environment=PATH=/usr/local/bin:/usr/bin:/bin
Environment=PYTHONPATH=/opt/2r-at-scanner
Environment=FLASK_APP=app.py
Environment=FLASK_ENV=production
Environment=DATABASE_PATH=/var/lib/2r-at/scanner.db
Environment=REDIS_URL=redis://localhost:6379/0
Environment=LOG_LEVEL=INFO

# Main application process
ExecStart=/opt/2r-at-scanner/start-scanner.sh
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/opt/2r-at-scanner/stop-scanner.sh

# Process management
PIDFile=/var/run/2r-at/scanner.pid
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30
RestartSec=10
Restart=always
RestartPreventExitStatus=0

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/2r-at /var/log/2r-at /var/run/2r-at /var/www/html/scan-results
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=false
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Resource limits
LimitNOFILE=65536
LimitNPROC=32768
MemoryMax=2G
CPUQuota=200%

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=2r-at-scanner

[Install]
WantedBy=multi-user.target
Also=2r-at-worker@.service
EOF

# Create worker service template
cat > /etc/systemd/system/2r-at-worker@.service << 'EOF'
[Unit]
Description=2R-AT Scanner Worker %i
Documentation=https://2r-at.com/docs
After=network.target redis.service 2r-at-scanner.service
Wants=redis.service
PartOf=2r-at-scanner.service
StopWhenUnneeded=true

[Service]
Type=simple
User=apache
Group=apache
WorkingDirectory=/opt/2r-at-scanner
Environment=PATH=/usr/local/bin:/usr/bin:/bin
Environment=PYTHONPATH=/opt/2r-at-scanner
Environment=WORKER_ID=%i
Environment=DATABASE_PATH=/var/lib/2r-at/scanner.db
Environment=REDIS_URL=redis://localhost:6379/0

ExecStart=/opt/2r-at-scanner/worker.py --worker-id=%i
ExecReload=/bin/kill -HUP $MAINPID

# Process management
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=60
RestartSec=5
Restart=always
RestartPreventExitStatus=0

# Security settings (same as main service)
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/2r-at /var/log/2r-at /var/www/html/scan-results
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=false
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Resource limits
LimitNOFILE=32768
LimitNPROC=16384
MemoryMax=1G
CPUQuota=100%

StandardOutput=journal
StandardError=journal
SyslogIdentifier=2r-at-worker-%i

[Install]
WantedBy=2r-at-scanner.service
EOF

# Create target for grouping services
cat > /etc/systemd/system/2r-at.target << 'EOF'
[Unit]
Description=2R-AT Security Platform Services
Documentation=https://2r-at.com/docs
Wants=httpd.service redis.service 2r-at-scanner.service
After=httpd.service redis.service

[Install]
WantedBy=multi-user.target
EOF

# Create startup script
mkdir -p /opt/2r-at-scanner
cat > /opt/2r-at-scanner/start-scanner.sh << 'EOF'
#!/bin/bash
# 2R-AT Scanner Service Startup Script

set -euo pipefail

# Configuration
INSTALL_DIR="/opt/2r-at-scanner"
PID_DIR="/var/run/2r-at"
LOG_DIR="/var/log/2r-at"
PID_FILE="$PID_DIR/scanner.pid"
LOG_FILE="$LOG_DIR/scanner.log"
WORKERS=3

# Colors for logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$1] $2" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$1"; }
log_error() { log "ERROR" "$1"; }
log_success() { log "SUCCESS" "$1"; }

# Ensure directories exist
mkdir -p "$PID_DIR" "$LOG_DIR"
chown apache:apache "$PID_DIR" "$LOG_DIR"

# Check if already running
if [[ -f "$PID_FILE" ]] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
    log_error "2R-AT Scanner is already running (PID: $(cat "$PID_FILE"))"
    exit 1
fi

# Check dependencies
if ! systemctl is-active --quiet redis; then
    log_error "Redis service is not running"
    exit 1
fi

if ! systemctl is-active --quiet httpd; then
    log_error "Apache service is not running"
    exit 1
fi

# Check database
if [[ ! -f "/var/lib/2r-at/scanner.db" ]]; then
    log_error "Database not found. Run database initialization first."
    exit 1
fi

# Check nuclei installation
if ! command -v nuclei >/dev/null 2>&1; then
    log_error "Nuclei scanner not found in PATH"
    exit 1
fi

log_info "Starting 2R-AT Security Platform Scanner..."

# Change to application directory
cd "$INSTALL_DIR"

# Set environment variables
export FLASK_APP=app.py
export FLASK_ENV=production
export DATABASE_PATH=/var/lib/2r-at/scanner.db
export REDIS_URL=redis://localhost:6379/0

# Start main application with gunicorn
log_info "Starting main API server..."
gunicorn \
    --bind 127.0.0.1:5000 \
    --workers 2 \
    --worker-class sync \
    --worker-connections 1000 \
    --max-requests 10000 \
    --max-requests-jitter 1000 \
    --timeout 300 \
    --keep-alive 5 \
    --user apache \
    --group apache \
    --pid "$PID_FILE" \
    --daemon \
    --access-logfile "$LOG_DIR/access.log" \
    --error-logfile "$LOG_DIR/error.log" \
    --log-level info \
    --capture-output \
    app:app

# Wait for main process to start
sleep 2

if [[ -f "$PID_FILE" ]] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
    log_success "2R-AT Scanner API started successfully (PID: $(cat "$PID_FILE"))"
    
    # Start worker processes
    log_info "Starting $WORKERS worker processes..."
    for ((i=1; i<=WORKERS; i++)); do
        systemctl start "2r-at-worker@$i.service"
    done
    
    log_success "All services started successfully"
    
    # Perform health check
    sleep 5
    if curl -sf http://127.0.0.1:5000/api/health >/dev/null; then
        log_success "Health check passed - service is responding"
    else
        log_error "Health check failed - service may not be working correctly"
    fi
    
else
    log_error "Failed to start 2R-AT Scanner"
    exit 1
fi
EOF

# Create stop script
cat > /opt/2r-at-scanner/stop-scanner.sh << 'EOF'
#!/bin/bash
# 2R-AT Scanner Service Stop Script

set -euo pipefail

# Configuration
PID_DIR="/var/run/2r-at"
LOG_DIR="/var/log/2r-at"
PID_FILE="$PID_DIR/scanner.pid"
LOG_FILE="$LOG_DIR/scanner.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$1] $2" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$1"; }
log_success() { log "SUCCESS" "$1"; }

log_info "Stopping 2R-AT Security Platform Scanner..."

# Stop worker processes first
log_info "Stopping worker processes..."
for worker in $(systemctl list-units --state=active 2r-at-worker@*.service --no-legend | awk '{print $1}'); do
    systemctl stop "$worker"
    log_info "Stopped $worker"
done

# Stop main process
if [[ -f "$PID_FILE" ]]; then
    local main_pid=$(cat "$PID_FILE")
    if kill -0 "$main_pid" 2>/dev/null; then
        log_info "Stopping main process (PID: $main_pid)..."
        kill -TERM "$main_pid"
        
        # Wait for graceful shutdown
        local count=0
        while kill -0 "$main_pid" 2>/dev/null && [[ $count -lt 30 ]]; do
            sleep 1
            ((count++))
        done
        
        # Force kill if still running
        if kill -0 "$main_pid" 2>/dev/null; then
            log_info "Force killing main process..."
            kill -KILL "$main_pid"
        fi
        
        rm -f "$PID_FILE"
        log_success "Main process stopped"
    else
        log_info "Main process not running"
        rm -f "$PID_FILE"
    fi
else
    log_info "PID file not found"
fi

log_success "2R-AT Scanner stopped successfully"
EOF

# Create worker script
cat > /opt/2r-at-scanner/worker.py << 'EOF'
#!/usr/bin/env python3
"""
2R-AT Scanner Worker Process
Handles background scan processing
"""

import os
import sys
import time
import json
import signal
import argparse
import logging
from datetime import datetime
from pathlib import Path

# Add the app directory to Python path
sys.path.insert(0, '/opt/2r-at-scanner')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/2r-at/worker.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(f'2r-at-worker')

class ScanWorker:
    def __init__(self, worker_id):
        self.worker_id = worker_id
        self.running = True
        self.logger = logging.getLogger(f'2r-at-worker-{worker_id}')
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGHUP, self.signal_handler)
        
        self.logger.info(f"Worker {worker_id} initialized")
    
    def signal_handler(self, signum, frame):
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def process_scan_queue(self):
        """Process pending scans from the queue"""
        try:
            # Import here to avoid issues if modules aren't available at startup
            from app import DatabaseManager, NucleiScanner
            import redis
            
            # Initialize connections
            db = DatabaseManager()
            scanner = NucleiScanner()
            redis_client = redis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379/0'))
            
            while self.running:
                try:
                    # Get pending scan from database
                    pending_scans = db.execute_query(
                        "SELECT id, target, scan_options FROM scans WHERE status = 'queued' ORDER BY created_at ASC LIMIT 1"
                    )
                    
                    if pending_scans:
                        scan = dict(pending_scans[0])
                        scan_id = scan['id']
                        target = scan['target']
                        scan_options = json.loads(scan['scan_options']) if scan['scan_options'] else {}
                        
                        self.logger.info(f"Processing scan {scan_id} for target {target}")
                        
                        # Mark scan as running
                        db.update_scan_status(scan_id, 'running')
                        
                        # Store worker info in Redis
                        redis_client.setex(f"scan:{scan_id}:worker", 3600, self.worker_id)
                        
                        # Execute scan
                        result = scanner.run_scan(target, scan_id, scan_options)
                        
                        # Clean up Redis
                        redis_client.delete(f"scan:{scan_id}:worker")
                        
                        self.logger.info(f"Scan {scan_id} completed with status: {result['status']}")
                    
                    else:
                        # No pending scans, wait before checking again
                        time.sleep(5)
                
                except Exception as e:
                    self.logger.error(f"Error processing scan queue: {str(e)}")
                    time.sleep(10)  # Wait longer on errors
        
        except ImportError as e:
            self.logger.error(f"Failed to import required modules: {str(e)}")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Fatal error in worker: {str(e)}")
            sys.exit(1)
    
    def run(self):
        """Main worker loop"""
        self.logger.info(f"Worker {self.worker_id} starting...")
        
        try:
            self.process_scan_queue()
        except KeyboardInterrupt:
            self.logger.info("Worker interrupted by user")
        except Exception as e:
            self.logger.error(f"Worker crashed: {str(e)}")
            raise
        finally:
            self.logger.info(f"Worker {self.worker_id} shutting down")

def main():
    parser = argparse.ArgumentParser(description='2R-AT Scanner Worker')
    parser.add_argument('--worker-id', required=True, help='Worker ID')
    args = parser.parse_args()
    
    worker = ScanWorker(args.worker_id)
    worker.run()

if __name__ == '__main__':
    main()
EOF

# Make scripts executable
chmod +x /opt/2r-at-scanner/start-scanner.sh
chmod +x /opt/2r-at-scanner/stop-scanner.sh
chmod +x /opt/2r-at-scanner/worker.py

# Set proper ownership
chown -R apache:apache /opt/2r-at-scanner

# Create runtime directories
mkdir -p /var/run/2r-at
chown apache:apache /var/run/2r-at

# Reload systemd and enable services
systemctl daemon-reload
systemctl enable 2r-at-scanner.service
systemctl enable 2r-at.target

echo "2R-AT systemd services configured successfully!"
echo ""
echo "Available commands:"
echo "  systemctl start 2r-at-scanner     # Start the scanner service"
echo "  systemctl stop 2r-at-scanner      # Stop the scanner service"
echo "  systemctl status 2r-at-scanner    # Check service status"
echo "  systemctl enable 2r-at.target     # Enable all 2R-AT services"
echo "  journalctl -u 2r-at-scanner -f    # View live logs"
