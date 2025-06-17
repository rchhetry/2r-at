#!/bin/bash
# ========================================
# 2R-AT Database Management Script
# Comprehensive database operations and maintenance
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
DATABASE_PATH="/var/lib/2r-at/scanner.db"
BACKUP_DIR="/opt/backups/2r-at"
LOG_DIR="/var/log/2r-at"
LOG_FILE="$LOG_DIR/database.log"

# Backup retention
DAILY_RETENTION=7    # Keep 7 daily backups
WEEKLY_RETENTION=4   # Keep 4 weekly backups
MONTHLY_RETENTION=12 # Keep 12 monthly backups

# Database schema version
CURRENT_SCHEMA_VERSION=2

print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
  ____  ____       _  _____   ____        _        _                    
 |___ \|  _ \     / \|_   _| |  _ \  __ _| |_ __ _| |__   __ _ ___  ___ 
   __) | |_) |   / _ \ | |   | | | |/ _` | __/ _` | '_ \ / _` / __|/ _ \
  / __/|  _ <   / ___ \| |   | |_| | (_| | || (_| | |_) | (_| \__ \  __/
 |_____|_| \_\ /_/   \_\_|   |____/ \__,_|\__\__,_|_.__/ \__,_|___/\___|
                                                                        
 __  __                                                   _   
|  \/  | __ _ _ __   __ _  __ _  ___ _ __ ___   ___ _ __ | |_ 
| |\/| |/ _` | '_ \ / _` |/ _` |/ _ \ '_ ` _ \ / _ \ '_ \| __|
| |  | | (_| | | | | (_| | (_| |  __/ | | | | |  __/ | | |_| 
|_|  |_|\__,_|_| |_|\__,_|\__, |\___|_| |_| |_|\___|_| |_|\__|
                          |___/                              
EOF
    echo -e "${NC}"
}

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "$@"; }
log_error() { log "ERROR" "$@"; }
log_success() { log "SUCCESS" "$@"; }

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if database exists and is accessible
check_database() {
    if [[ ! -f "$DATABASE_PATH" ]]; then
        print_error "Database file not found: $DATABASE_PATH"
        return 1
    fi
    
    if [[ ! -r "$DATABASE_PATH" ]]; then
        print_error "Database file not readable: $DATABASE_PATH"
        return 1
    fi
    
    if [[ ! -w "$DATABASE_PATH" ]]; then
        print_error "Database file not writable: $DATABASE_PATH"
        return 1
    fi
    
    # Test database connectivity
    if ! sqlite3 "$DATABASE_PATH" "SELECT 1;" >/dev/null 2>&1; then
        print_error "Database connectivity test failed"
        return 1
    fi
    
    return 0
}

# Get database schema version
get_schema_version() {
    sqlite3 "$DATABASE_PATH" "PRAGMA user_version;" 2>/dev/null || echo "0"
}

# Set database schema version
set_schema_version() {
    local version="$1"
    sqlite3 "$DATABASE_PATH" "PRAGMA user_version = $version;"
    log_info "Schema version updated to $version"
}

# Initialize database with schema
init_database() {
    print_status "Initializing database schema..."
    
    if [[ -f "$DATABASE_PATH" ]]; then
        read -p "Database already exists. Recreate? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Database initialization cancelled"
            return 0
        fi
        
        # Backup existing database
        local backup_file="$BACKUP_DIR/pre-init-$(date +%Y%m%d_%H%M%S).db"
        mkdir -p "$BACKUP_DIR"
        cp "$DATABASE_PATH" "$backup_file"
        print_status "Existing database backed up to: $backup_file"
    fi
    
    # Create database with schema
    sqlite3 "$DATABASE_PATH" << 'EOF'
-- Users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    company TEXT DEFAULT '',
    role TEXT DEFAULT 'user',
    user_role TEXT,
    plan TEXT DEFAULT 'basic',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT 1,
    scan_quota INTEGER DEFAULT 10,
    scans_used INTEGER DEFAULT 0,
    settings TEXT DEFAULT '{}',
    api_key TEXT,
    email_verified BOOLEAN DEFAULT 0,
    two_factor_enabled BOOLEAN DEFAULT 0,
    last_password_change TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    target TEXT NOT NULL,
    scan_name TEXT DEFAULT '',
    scan_type TEXT DEFAULT 'full',
    status TEXT DEFAULT 'queued',
    priority INTEGER DEFAULT 5,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    result_data TEXT,
    error_message TEXT,
    scan_options TEXT DEFAULT '{}',
    progress INTEGER DEFAULT 0,
    estimated_completion TIMESTAMP,
    scan_duration INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    tags TEXT DEFAULT '',
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- User statistics table
CREATE TABLE IF NOT EXISTS user_stats (
    user_id TEXT PRIMARY KEY,
    scans_completed INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    last_scan_date TIMESTAMP,
    total_scan_time INTEGER DEFAULT 0,
    average_scan_time INTEGER DEFAULT 0,
    critical_vulns INTEGER DEFAULT 0,
    high_vulns INTEGER DEFAULT 0,
    medium_vulns INTEGER DEFAULT 0,
    low_vulns INTEGER DEFAULT 0,
    info_vulns INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Vulnerability reports table
CREATE TABLE IF NOT EXISTS vulnerability_reports (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    matched_at TEXT NOT NULL,
    cvss_score REAL DEFAULT 0.0,
    cve_id TEXT,
    reference_urls TEXT DEFAULT '[]',
    fix_recommendation TEXT,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified BOOLEAN DEFAULT 0,
    false_positive BOOLEAN DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

-- API usage tracking
CREATE TABLE IF NOT EXISTS api_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response_time INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
);

-- System audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    details TEXT DEFAULT '{}',
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
);

-- Security events
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_ip TEXT,
    user_id TEXT,
    description TEXT NOT NULL,
    details TEXT DEFAULT '{}',
    resolved BOOLEAN DEFAULT 0,
    resolved_at TIMESTAMP,
    resolved_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
);

-- System configuration
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

CREATE INDEX IF NOT EXISTS idx_vulnerability_reports_scan_id ON vulnerability_reports(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerability_reports_severity ON vulnerability_reports(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerability_reports_template_id ON vulnerability_reports(template_id);
CREATE INDEX IF NOT EXISTS idx_vulnerability_reports_cve_id ON vulnerability_reports(cve_id);

CREATE INDEX IF NOT EXISTS idx_api_usage_user_id ON api_usage(user_id);
CREATE INDEX IF NOT EXISTS idx_api_usage_created_at ON api_usage(created_at);
CREATE INDEX IF NOT EXISTS idx_api_usage_endpoint ON api_usage(endpoint);

CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);

CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_resolved ON security_events(resolved);

-- Insert default system configuration
INSERT OR REPLACE INTO system_config (key, value, description) VALUES 
    ('platform_name', '2R-AT Security Platform', 'Platform display name'),
    ('max_scan_duration', '3600', 'Maximum scan duration in seconds'),
    ('default_scan_quota', '10', 'Default scan quota for new users'),
    ('api_rate_limit', '100', 'API rate limit per hour'),
    ('session_timeout', '86400', 'Session timeout in seconds'),
    ('password_min_length', '8', 'Minimum password length'),
    ('email_notifications', '1', 'Enable email notifications'),
    ('auto_cleanup_days', '90', 'Auto cleanup completed scans after days'),
    ('max_concurrent_scans', '5', 'Maximum concurrent scans per user');

-- Create triggers for audit logging
CREATE TRIGGER IF NOT EXISTS users_audit_insert 
AFTER INSERT ON users 
BEGIN
    INSERT INTO audit_log (user_id, action, resource_type, resource_id, details) 
    VALUES (NEW.id, 'CREATE', 'user', NEW.id, json_object('email', NEW.email, 'name', NEW.name));
END;

CREATE TRIGGER IF NOT EXISTS users_audit_update 
AFTER UPDATE ON users 
BEGIN
    INSERT INTO audit_log (user_id, action, resource_type, resource_id, details) 
    VALUES (NEW.id, 'UPDATE', 'user', NEW.id, json_object('changed_fields', 'multiple'));
END;

CREATE TRIGGER IF NOT EXISTS scans_audit_insert 
AFTER INSERT ON scans 
BEGIN
    INSERT INTO audit_log (user_id, action, resource_type, resource_id, details) 
    VALUES (NEW.user_id, 'CREATE', 'scan', NEW.id, json_object('target', NEW.target, 'scan_name', NEW.scan_name));
END;

-- Set schema version
PRAGMA user_version = 2;
EOF
    
    # Set proper permissions
    chown apache:apache "$DATABASE_PATH"
    chmod 664 "$DATABASE_PATH"
    
    log_success "Database initialized with schema version $CURRENT_SCHEMA_VERSION"
    print_success "Database initialization completed successfully"
}

# Upgrade database schema
upgrade_schema() {
    local current_version=$(get_schema_version)
    
    print_status "Current schema version: $current_version"
    print_status "Target schema version: $CURRENT_SCHEMA_VERSION"
    
    if [[ $current_version -eq $CURRENT_SCHEMA_VERSION ]]; then
        print_status "Database schema is already up to date"
        return 0
    fi
    
    if [[ $current_version -gt $CURRENT_SCHEMA_VERSION ]]; then
        print_error "Database schema version ($current_version) is newer than supported version ($CURRENT_SCHEMA_VERSION)"
        return 1
    fi
    
    # Create backup before upgrade
    create_backup "pre-upgrade-v${current_version}-to-v${CURRENT_SCHEMA_VERSION}"
    
    print_status "Upgrading database schema from version $current_version to $CURRENT_SCHEMA_VERSION..."
    
    # Apply migrations based on current version
    case $current_version in
        0)
            print_status "Applying migration: 0 -> 1"
            sqlite3 "$DATABASE_PATH" << 'EOF'
-- Migration from version 0 to 1
ALTER TABLE users ADD COLUMN settings TEXT DEFAULT '{}';
ALTER TABLE users ADD COLUMN api_key TEXT;
ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT 0;
ALTER TABLE users ADD COLUMN two_factor_enabled BOOLEAN DEFAULT 0;
ALTER TABLE users ADD COLUMN last_password_change TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE scans ADD COLUMN scan_type TEXT DEFAULT 'full';
ALTER TABLE scans ADD COLUMN priority INTEGER DEFAULT 5;
ALTER TABLE scans ADD COLUMN scan_options TEXT DEFAULT '{}';
ALTER TABLE scans ADD COLUMN progress INTEGER DEFAULT 0;
ALTER TABLE scans ADD COLUMN estimated_completion TIMESTAMP;
ALTER TABLE scans ADD COLUMN scan_duration INTEGER DEFAULT 0;
ALTER TABLE scans ADD COLUMN vulnerabilities_found INTEGER DEFAULT 0;
ALTER TABLE scans ADD COLUMN tags TEXT DEFAULT '';

PRAGMA user_version = 1;
EOF
            ;&  # Fall through to next migration
        1)
            print_status "Applying migration: 1 -> 2"
            sqlite3 "$DATABASE_PATH" << 'EOF'
-- Migration from version 1 to 2
-- Create new tables introduced in v2
CREATE TABLE IF NOT EXISTS vulnerability_reports (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    matched_at TEXT NOT NULL,
    cvss_score REAL DEFAULT 0.0,
    cve_id TEXT,
    reference_urls TEXT DEFAULT '[]',
    fix_recommendation TEXT,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified BOOLEAN DEFAULT 0,
    false_positive BOOLEAN DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS api_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response_time INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    details TEXT DEFAULT '{}',
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_ip TEXT,
    user_id TEXT,
    description TEXT NOT NULL,
    details TEXT DEFAULT '{}',
    resolved BOOLEAN DEFAULT 0,
    resolved_at TIMESTAMP,
    resolved_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by TEXT
);

-- Add new indexes
CREATE INDEX IF NOT EXISTS idx_vulnerability_reports_scan_id ON vulnerability_reports(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerability_reports_severity ON vulnerability_reports(severity);
CREATE INDEX IF NOT EXISTS idx_api_usage_user_id ON api_usage(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at);

-- Update user_stats table with new columns
ALTER TABLE user_stats ADD COLUMN average_scan_time INTEGER DEFAULT 0;
ALTER TABLE user_stats ADD COLUMN critical_vulns INTEGER DEFAULT 0;
ALTER TABLE user_stats ADD COLUMN high_vulns INTEGER DEFAULT 0;
ALTER TABLE user_stats ADD COLUMN medium_vulns INTEGER DEFAULT 0;
ALTER TABLE user_stats ADD COLUMN low_vulns INTEGER DEFAULT 0;
ALTER TABLE user_stats ADD COLUMN info_vulns INTEGER DEFAULT 0;

PRAGMA user_version = 2;
EOF
            ;;
    esac
    
    set_schema_version $CURRENT_SCHEMA_VERSION
    print_success "Database schema upgraded successfully to version $CURRENT_SCHEMA_VERSION"
}

# Create database backup
create_backup() {
    local backup_type="${1:-manual}"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$BACKUP_DIR/${backup_type}_${timestamp}.db"
    
    if ! check_database; then
        print_error "Cannot create backup: database check failed"
        return 1
    fi
    
    mkdir -p "$BACKUP_DIR"
    
    print_status "Creating backup: $backup_file"
    
    # Use SQLite backup command for consistency
    sqlite3 "$DATABASE_PATH" ".backup '$backup_file'"
    
    if [[ -f "$backup_file" ]]; then
        # Compress backup
        gzip "$backup_file"
        backup_file="${backup_file}.gz"
        
        # Set proper permissions
        chmod 600 "$backup_file"
        
        local backup_size=$(du -h "$backup_file" | cut -f1)
        log_success "Backup created: $backup_file (Size: $backup_size)"
        print_success "Backup created successfully: $backup_file"
        
        # Create backup metadata
        cat > "${backup_file}.meta" << EOF
{
    "backup_type": "$backup_type",
    "timestamp": "$timestamp",
    "database_path": "$DATABASE_PATH",
    "backup_size": "$backup_size",
    "schema_version": "$(get_schema_version)",
    "created_by": "$(whoami)",
    "hostname": "$(hostname)"
}
EOF
        
        echo "$backup_file"
    else
        print_error "Backup creation failed"
        return 1
    fi
}

# Restore database from backup
restore_backup() {
    local backup_file="$1"
    
    if [[ -z "$backup_file" ]]; then
        print_error "Backup file not specified"
        return 1
    fi
    
    if [[ ! -f "$backup_file" ]]; then
        print_error "Backup file not found: $backup_file"
        return 1
    fi
    
    print_warning "This will replace the current database!"
    read -p "Continue with restore? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Restore cancelled"
        return 0
    fi
    
    # Create current backup before restore
    create_backup "pre-restore"
    
    print_status "Restoring database from: $backup_file"
    
    # Handle compressed backups
    local temp_file="$backup_file"
    if [[ "$backup_file" == *.gz ]]; then
        temp_file="/tmp/restore_$(basename "$backup_file" .gz)"
        gunzip -c "$backup_file" > "$temp_file"
    fi
    
    # Stop services that might be using the database
    if systemctl is-active --quiet 2r-at-scanner 2>/dev/null; then
        print_status "Stopping 2R-AT scanner service..."
        systemctl stop 2r-at-scanner
        local restart_service=true
    fi
    
    # Restore database
    cp "$temp_file" "$DATABASE_PATH"
    
    # Set proper permissions
    chown apache:apache "$DATABASE_PATH"
    chmod 664 "$DATABASE_PATH"
    
    # Clean up temp file if created
    if [[ "$temp_file" != "$backup_file" ]]; then
        rm -f "$temp_file"
    fi
    
    # Restart service if it was stopped
    if [[ "${restart_service:-false}" == "true" ]]; then
        print_status "Starting 2R-AT scanner service..."
        systemctl start 2r-at-scanner
    fi
    
    # Verify restoration
    if check_database; then
        log_success "Database restored from backup: $backup_file"
        print_success "Database restoration completed successfully"
    else
        print_error "Database restoration failed - database check failed"
        return 1
    fi
}

# List available backups
list_backups() {
    print_status "Available backups in $BACKUP_DIR:"
    echo ""
    
    if [[ ! -d "$BACKUP_DIR" ]]; then
        print_warning "Backup directory does not exist: $BACKUP_DIR"
        return 0
    fi
    
    local backups=($(find "$BACKUP_DIR" -name "*.db.gz" -o -name "*.db" | sort -r))
    
    if [[ ${#backups[@]} -eq 0 ]]; then
        print_warning "No backups found"
        return 0
    fi
    
    printf "%-20s %-20s %-10s %-15s\n" "Type" "Date" "Size" "File"
    printf "%-20s %-20s %-10s %-15s\n" "----" "----" "----" "----"
    
    for backup in "${backups[@]}"; do
        local basename=$(basename "$backup")
        local type=$(echo "$basename" | cut -d'_' -f1)
        local date_part=$(echo "$basename" | cut -d'_' -f2 | cut -d'.' -f1)
        local formatted_date="${date_part:0:4}-${date_part:4:2}-${date_part:6:2} ${date_part:9:2}:${date_part:11:2}"
        local size=$(du -h "$backup" | cut -f1)
        
        printf "%-20s %-20s %-10s %-15s\n" "$type" "$formatted_date" "$size" "$basename"
    done
}

# Clean up old backups
cleanup_backups() {
    print_status "Cleaning up old backups..."
    
    if [[ ! -d "$BACKUP_DIR" ]]; then
        print_warning "Backup directory does not exist: $BACKUP_DIR"
        return 0
    fi
    
    local removed_count=0
    
    # Clean daily backups (keep last N)
    local daily_backups=($(find "$BACKUP_DIR" -name "daily_*.db.gz" | sort -r))
    if [[ ${#daily_backups[@]} -gt $DAILY_RETENTION ]]; then
        for ((i=$DAILY_RETENTION; i<${#daily_backups[@]}; i++)); do
            rm -f "${daily_backups[$i]}" "${daily_backups[$i]}.meta"
            log_info "Removed old daily backup: $(basename "${daily_backups[$i]}")"
            ((removed_count++))
        done
    fi
    
    # Clean weekly backups (keep last N)
    local weekly_backups=($(find "$BACKUP_DIR" -name "weekly_*.db.gz" | sort -r))
    if [[ ${#weekly_backups[@]} -gt $WEEKLY_RETENTION ]]; then
        for ((i=$WEEKLY_RETENTION; i<${#weekly_backups[@]}; i++)); do
            rm -f "${weekly_backups[$i]}" "${weekly_backups[$i]}.meta"
            log_info "Removed old weekly backup: $(basename "${weekly_backups[$i]}")"
            ((removed_count++))
        done
    fi
    
    # Clean monthly backups (keep last N)
    local monthly_backups=($(find "$BACKUP_DIR" -name "monthly_*.db.gz" | sort -r))
    if [[ ${#monthly_backups[@]} -gt $MONTHLY_RETENTION ]]; then
        for ((i=$MONTHLY_RETENTION; i<${#monthly_backups[@]}; i++)); do
            rm -f "${monthly_backups[$i]}" "${monthly_backups[$i]}.meta"
            log_info "Removed old monthly backup: $(basename "${monthly_backups[$i]}")"
            ((removed_count++))
        done
    fi
    
    # Clean orphaned metadata files
    find "$BACKUP_DIR" -name "*.meta" | while read -r meta_file; do
        local backup_file="${meta_file%.meta}"
        if [[ ! -f "$backup_file" ]]; then
            rm -f "$meta_file"
            log_info "Removed orphaned metadata: $(basename "$meta_file")"
            ((removed_count++))
        fi
    done
    
    print_success "Cleanup completed. Removed $removed_count old backup files."
}

# Database maintenance operations
maintain_database() {
    print_status "Starting database maintenance..."
    
    if ! check_database; then
        print_error "Database check failed. Aborting maintenance."
        return 1
    fi
    
    # Create maintenance backup
    create_backup "maintenance"
    
    print_status "Running VACUUM to optimize database..."
    sqlite3 "$DATABASE_PATH" "VACUUM;"
    
    print_status "Analyzing database statistics..."
    sqlite3 "$DATABASE_PATH" "ANALYZE;"
    
    print_status "Checking database integrity..."
    local integrity_check=$(sqlite3 "$DATABASE_PATH" "PRAGMA integrity_check;")
    if [[ "$integrity_check" == "ok" ]]; then
        print_success "Database integrity check passed"
    else
        print_error "Database integrity check failed: $integrity_check"
        return 1
    fi
    
    # Clean up old records
    print_status "Cleaning up old records..."
    
    # Remove API usage records older than 30 days
    local deleted_api_usage=$(sqlite3 "$DATABASE_PATH" "DELETE FROM api_usage WHERE created_at < datetime('now', '-30 days'); SELECT changes();")
    log_info "Deleted $deleted_api_usage old API usage records"
    
    # Remove audit log entries older than 90 days
    local deleted_audit=$(sqlite3 "$DATABASE_PATH" "DELETE FROM audit_log WHERE created_at < datetime('now', '-90 days'); SELECT changes();")
    log_info "Deleted $deleted_audit old audit log entries"
    
    # Remove resolved security events older than 60 days
    local deleted_security=$(sqlite3 "$DATABASE_PATH" "DELETE FROM security_events WHERE resolved = 1 AND resolved_at < datetime('now', '-60 days'); SELECT changes();")
    log_info "Deleted $deleted_security old resolved security events"
    
    # Update user statistics
    print_status "Updating user statistics..."
    sqlite3 "$DATABASE_PATH" << 'EOF'
UPDATE user_stats SET 
    scans_completed = (SELECT COUNT(*) FROM scans WHERE user_id = user_stats.user_id AND status = 'completed'),
    vulnerabilities_found = (SELECT COALESCE(SUM(vulnerabilities_found), 0) FROM scans WHERE user_id = user_stats.user_id AND status = 'completed'),
    total_scan_time = (SELECT COALESCE(SUM(scan_duration), 0) FROM scans WHERE user_id = user_stats.user_id AND status = 'completed'),
    last_scan_date = (SELECT MAX(completed_at) FROM scans WHERE user_id = user_stats.user_id AND status = 'completed');

UPDATE user_stats SET 
    average_scan_time = CASE WHEN scans_completed > 0 THEN total_scan_time / scans_completed ELSE 0 END;
EOF
    
    print_success "Database maintenance completed successfully"
}

# Get database statistics
show_statistics() {
    if ! check_database; then
        print_error "Database check failed"
        return 1
    fi
    
    print_banner
    echo -e "${CYAN}Database Statistics${NC}"
    echo "==================="
    echo ""
    
    # Database file info
    local db_size=$(du -h "$DATABASE_PATH" | cut -f1)
    local schema_version=$(get_schema_version)
    echo "Database file: $DATABASE_PATH"
    echo "Database size: $db_size"
    echo "Schema version: $schema_version"
    echo ""
    
    # Table statistics
    echo -e "${BLUE}Table Statistics:${NC}"
    sqlite3 "$DATABASE_PATH" << 'EOF'
.headers on
.mode column
SELECT 
    name as "Table",
    (SELECT COUNT(*) FROM pragma_table_info(name)) as "Columns",
    '' as "Records"
FROM sqlite_master 
WHERE type='table' AND name NOT LIKE 'sqlite_%'
ORDER BY name;
EOF
    
    echo ""
    
    # Record counts
    echo -e "${BLUE}Record Counts:${NC}"
    printf "%-20s %s\n" "Table" "Count"
    printf "%-20s %s\n" "-----" "-----"
    
    local tables=(users scans user_stats vulnerability_reports api_usage audit_log security_events system_config)
    for table in "${tables[@]}"; do
        local count=$(sqlite3 "$DATABASE_PATH" "SELECT COUNT(*) FROM $table;" 2>/dev/null || echo "N/A")
        printf "%-20s %s\n" "$table" "$count"
    done
    
    echo ""
    
    # Scan statistics
    echo -e "${BLUE}Scan Statistics:${NC}"
    sqlite3 "$DATABASE_PATH" << 'EOF'
.headers on
.mode column
SELECT 
    status as "Status",
    COUNT(*) as "Count"
FROM scans 
GROUP BY status 
ORDER BY status;
EOF
    
    echo ""
    
    # User statistics
    echo -e "${BLUE}User Statistics:${NC}"
    sqlite3 "$DATABASE_PATH" << 'EOF'
.headers on
.mode column
SELECT 
    role as "Role",
    COUNT(*) as "Count",
    SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as "Active"
FROM users 
GROUP BY role 
ORDER BY role;
EOF
    
    echo ""
    
    # Recent activity
    echo -e "${BLUE}Recent Activity (Last 24 Hours):${NC}"
    local recent_scans=$(sqlite3 "$DATABASE_PATH" "SELECT COUNT(*) FROM scans WHERE created_at > datetime('now', '-1 day');")
    local recent_users=$(sqlite3 "$DATABASE_PATH" "SELECT COUNT(*) FROM users WHERE last_login > datetime('now', '-1 day');")
    local recent_vulns=$(sqlite3 "$DATABASE_PATH" "SELECT COUNT(*) FROM vulnerability_reports WHERE discovered_at > datetime('now', '-1 day');")
    
    echo "New scans: $recent_scans"
    echo "Active users: $recent_users"
    echo "New vulnerabilities: $recent_vulns"
    
    echo ""
    echo -e "${CYAN}===================${NC}"
}

# Export database data
export_data() {
    local export_type="${1:-csv}"
    local export_dir="/tmp/2r-at-export-$(date +%Y%m%d_%H%M%S)"
    
    if ! check_database; then
        print_error "Database check failed"
        return 1
    fi
    
    mkdir -p "$export_dir"
    
    print_status "Exporting database data to: $export_dir"
    
    case $export_type in
        "csv")
            # Export main tables to CSV
            local tables=(users scans user_stats vulnerability_reports audit_log)
            for table in "${tables[@]}"; do
                print_status "Exporting table: $table"
                sqlite3 "$DATABASE_PATH" << EOF
.headers on
.mode csv
.output $export_dir/${table}.csv
SELECT * FROM $table;
EOF
            done
            ;;
        "json")
            # Export to JSON format (requires jq)
            if ! command -v jq >/dev/null 2>&1; then
                print_error "jq is required for JSON export"
                return 1
            fi
            
            print_status "Exporting to JSON format..."
            # Implementation would go here
            print_warning "JSON export not yet implemented"
            ;;
        "sql")
            # Export as SQL dump
            print_status "Creating SQL dump..."
            sqlite3 "$DATABASE_PATH" .dump > "$export_dir/database_dump.sql"
            ;;
        *)
            print_error "Unknown export type: $export_type"
            return 1
            ;;
    esac
    
    # Create export metadata
    cat > "$export_dir/export_metadata.txt" << EOF
Export Type: $export_type
Export Date: $(date)
Database: $DATABASE_PATH
Schema Version: $(get_schema_version)
Exported by: $(whoami)
Server: $(hostname)
EOF
    
    print_success "Data export completed: $export_dir"
}

# Main execution
main() {
    local command="${1:-help}"
    
    # Ensure log directory exists
    mkdir -p "$LOG_DIR"
    
    case $command in
        "init"|"initialize")
            init_database
            ;;
        "upgrade")
            upgrade_schema
            ;;
        "backup")
            local backup_type="${2:-manual}"
            create_backup "$backup_type"
            ;;
        "restore")
            local backup_file="$2"
            restore_backup "$backup_file"
            ;;
        "list-backups"|"backups")
            list_backups
            ;;
        "cleanup")
            cleanup_backups
            ;;
        "maintain"|"maintenance")
            maintain_database
            ;;
        "status"|"stats"|"statistics")
            show_statistics
            ;;
        "check")
            if check_database; then
                print_success "Database check passed"
                show_statistics
            else
                print_error "Database check failed"
                exit 1
            fi
            ;;
        "export")
            local export_type="${2:-csv}"
            export_data "$export_type"
            ;;
        "help"|"-h"|"--help")
            cat << EOF
2R-AT Database Management Script

Usage: $0 [COMMAND] [OPTIONS]

Commands:
  init, initialize     Initialize database with schema
  upgrade             Upgrade database schema to latest version
  backup [type]       Create database backup (type: manual, daily, weekly, monthly)
  restore <file>      Restore database from backup file
  list-backups        List available backup files
  cleanup             Clean up old backup files
  maintain            Run database maintenance operations
  status, stats       Show database statistics
  check               Check database health and show statistics
  export [format]     Export database data (format: csv, json, sql)
  help                Show this help message

Examples:
  $0 init                          # Initialize new database
  $0 backup daily                  # Create daily backup
  $0 restore backup_file.db.gz     # Restore from backup
  $0 maintain                      # Run maintenance
  $0 export csv                    # Export to CSV format

Configuration:
  Database: $DATABASE_PATH
  Backups: $BACKUP_DIR
  Logs: $LOG_FILE

EOF
            ;;
        *)
            print_error "Unknown command: $command"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"