#!/bin/bash
# ========================================
# 2R-AT Advanced Monitoring Script
# Comprehensive system health monitoring and alerting
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
SCRIPT_NAME="2r-at-advanced-monitor"
LOG_FILE="/var/log/2r-at/monitoring.log"
CONFIG_FILE="/etc/2r-at/monitoring.conf"
STATE_FILE="/var/lib/2r-at/monitoring.state"
ALERTS_FILE="/var/lib/2r-at/alerts.json"
METRICS_FILE="/var/lib/2r-at/metrics.json"

# Default thresholds (can be overridden in config file)
CPU_THRESHOLD=80
MEMORY_THRESHOLD=85
DISK_THRESHOLD=90
LOAD_THRESHOLD=5.0
API_RESPONSE_THRESHOLD=5000  # milliseconds
ERROR_RATE_THRESHOLD=10      # percent

# Email configuration
SMTP_SERVER="localhost"
SMTP_PORT="587"
FROM_EMAIL="noreply@2r-at.com"
ADMIN_EMAIL="admin@2r-at.com"

# Slack webhook (if configured)
SLACK_WEBHOOK=""

# Initialize logging
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
log_debug() { log "DEBUG" "$@"; }

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        log_debug "Configuration loaded from $CONFIG_FILE"
    else
        log_info "No configuration file found at $CONFIG_FILE, using defaults"
    fi
}

# Initialize monitoring state
init_state() {
    mkdir -p "$(dirname "$STATE_FILE")"
    mkdir -p "$(dirname "$ALERTS_FILE")"
    mkdir -p "$(dirname "$METRICS_FILE")"
    
    if [[ ! -f "$STATE_FILE" ]]; then
        echo '{"last_check": 0, "uptime_start": 0}' > "$STATE_FILE"
    fi
    
    if [[ ! -f "$ALERTS_FILE" ]]; then
        echo '{"active_alerts": [], "alert_history": []}' > "$ALERTS_FILE"
    fi
    
    if [[ ! -f "$METRICS_FILE" ]]; then
        echo '{"cpu": [], "memory": [], "disk": [], "api_response": []}' > "$METRICS_FILE"
    fi
}

# System health checks
check_system_resources() {
    local status="OK"
    local issues=()
    
    # CPU usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    cpu_usage=${cpu_usage%.*}  # Remove decimal
    
    if [[ $cpu_usage -gt $CPU_THRESHOLD ]]; then
        issues+=("High CPU usage: ${cpu_usage}%")
        status="CRITICAL"
    fi
    
    # Memory usage
    local memory_info=$(free | grep Mem)
    local total_mem=$(echo $memory_info | awk '{print $2}')
    local used_mem=$(echo $memory_info | awk '{print $3}')
    local memory_usage=$((used_mem * 100 / total_mem))
    
    if [[ $memory_usage -gt $MEMORY_THRESHOLD ]]; then
        issues+=("High memory usage: ${memory_usage}%")
        [[ "$status" != "CRITICAL" ]] && status="WARNING"
    fi
    
    # Disk usage
    local disk_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    
    if [[ $disk_usage -gt $DISK_THRESHOLD ]]; then
        issues+=("High disk usage: ${disk_usage}%")
        status="CRITICAL"
    fi
    
    # Load average
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    
    if (( $(echo "$load_avg > $LOAD_THRESHOLD" | bc -l) )); then
        issues+=("High load average: $load_avg")
        [[ "$status" != "CRITICAL" ]] && status="WARNING"
    fi
    
    # Store metrics
    store_metric "cpu" "$cpu_usage"
    store_metric "memory" "$memory_usage"
    store_metric "disk" "$disk_usage"
    
    echo "$status|$(IFS=';'; echo "${issues[*]}")|CPU:${cpu_usage}%,MEM:${memory_usage}%,DISK:${disk_usage}%,LOAD:${load_avg}"
}

# Check service health
check_services() {
    local status="OK"
    local issues=()
    
    # Critical services
    local services=("httpd" "redis" "firewalld")
    
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            issues+=("Service $service is not running")
            status="CRITICAL"
        fi
    done
    
    # Check 2r-at-scanner if it exists
    if systemctl list-unit-files | grep -q "2r-at-scanner.service"; then
        if ! systemctl is-active --quiet "2r-at-scanner"; then
            issues+=("2R-AT Scanner service is not running")
            status="CRITICAL"
        fi
    fi
    
    echo "$status|$(IFS=';'; echo "${issues[*]}")"
}

# Check network connectivity
check_network() {
    local status="OK"
    local issues=()
    
    # Check if ports are listening
    local ports=("80" "443" "6379")  # HTTP, HTTPS, Redis
    
    for port in "${ports[@]}"; do
        if ! netstat -tuln | grep -q ":$port "; then
            issues+=("Port $port is not listening")
            [[ "$status" != "CRITICAL" ]] && status="WARNING"
        fi
    done
    
    # Check external connectivity
    if ! ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        issues+=("No external network connectivity")
        status="CRITICAL"
    fi
    
    echo "$status|$(IFS=';'; echo "${issues[*]}")"
}

# Check API health
check_api_health() {
    local status="OK"
    local issues=()
    local response_time=0
    
    # Check API endpoint
    local start_time=$(date +%s%3N)
    local http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "http://127.0.0.1:5000/api/health" 2>/dev/null || echo "000")
    local end_time=$(date +%s%3N)
    response_time=$((end_time - start_time))
    
    if [[ "$http_code" != "200" ]]; then
        issues+=("API health check failed (HTTP $http_code)")
        status="CRITICAL"
    elif [[ $response_time -gt $API_RESPONSE_THRESHOLD ]]; then
        issues+=("API response time too slow: ${response_time}ms")
        [[ "$status" != "CRITICAL" ]] && status="WARNING"
    fi
    
    # Store API response time metric
    store_metric "api_response" "$response_time"
    
    echo "$status|$(IFS=';'; echo "${issues[*]}")|RESPONSE_TIME:${response_time}ms"
}

# Check database health
check_database() {
    local status="OK"
    local issues=()
    local db_file="/var/lib/2r-at/scanner.db"
    
    # Check if database file exists and is readable
    if [[ ! -f "$db_file" ]]; then
        issues+=("Database file not found")
        status="CRITICAL"
    elif [[ ! -r "$db_file" ]]; then
        issues+=("Database file not readable")
        status="CRITICAL"
    else
        # Try to query database
        if ! sqlite3 "$db_file" "SELECT 1;" >/dev/null 2>&1; then
            issues+=("Database query failed")
            status="CRITICAL"
        fi
        
        # Check database size
        local db_size=$(du -h "$db_file" | cut -f1)
        log_debug "Database size: $db_size"
    fi
    
    echo "$status|$(IFS=';'; echo "${issues[*]}")"
}

# Check log files
check_logs() {
    local status="OK"
    local issues=()
    local log_dir="/var/log/2r-at"
    
    # Check if log directory exists
    if [[ ! -d "$log_dir" ]]; then
        issues+=("Log directory not found")
        status="WARNING"
    else
        # Check for recent errors in logs
        local error_count=0
        if [[ -f "$log_dir/scanner.log" ]]; then
            # Count errors in last 15 minutes
            error_count=$(grep -c "ERROR" "$log_dir/scanner.log" 2>/dev/null | tail -100 || echo "0")
        fi
        
        if [[ $error_count -gt 5 ]]; then
            issues+=("High error rate in logs: $error_count errors")
            [[ "$status" != "CRITICAL" ]] && status="WARNING"
        fi
    fi
    
    echo "$status|$(IFS=';'; echo "${issues[*]}")"
}

# Check security
check_security() {
    local status="OK"
    local issues=()
    
    # Check firewall status
    if ! firewall-cmd --state >/dev/null 2>&1; then
        issues+=("Firewall is not running")
        status="WARNING"
    fi
    
    # Check for failed login attempts
    local failed_logins=$(journalctl --since "15 minutes ago" | grep -c "Failed password" 2>/dev/null || echo "0")
    if [[ $failed_logins -gt 10 ]]; then
        issues+=("High number of failed login attempts: $failed_logins")
        [[ "$status" != "CRITICAL" ]] && status="WARNING"
    fi
    
    # Check SSL certificate expiry (if configured)
    if [[ -f "/etc/letsencrypt/live/2r-at.com/cert.pem" ]]; then
        local cert_expiry=$(openssl x509 -enddate -noout -in /etc/letsencrypt/live/2r-at.com/cert.pem | cut -d= -f2)
        local expiry_epoch=$(date -d "$cert_expiry" +%s)
        local current_epoch=$(date +%s)
        local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
        
        if [[ $days_until_expiry -lt 7 ]]; then
            issues+=("SSL certificate expires in $days_until_expiry days")
            status="WARNING"
        fi
    fi
    
    echo "$status|$(IFS=';'; echo "${issues[*]}")"
}

# Store metric data
store_metric() {
    local metric_type="$1"
    local value="$2"
    local timestamp=$(date +%s)
    
    # Create temporary file with updated metrics
    local temp_file=$(mktemp)
    jq --arg type "$metric_type" --argjson value "$value" --argjson ts "$timestamp" \
       '.[$type] += [{"timestamp": $ts, "value": $value}] | .[$type] = (.[$type] | sort_by(.timestamp) | if length > 100 then .[1:] else . end)' \
       "$METRICS_FILE" > "$temp_file" 2>/dev/null || {
        # If jq fails, create basic structure
        echo "{\"$metric_type\": [{\"timestamp\": $timestamp, \"value\": $value}]}" > "$temp_file"
    }
    
    mv "$temp_file" "$METRICS_FILE"
}

# Alert management
create_alert() {
    local component="$1"
    local severity="$2"
    local message="$3"
    local timestamp=$(date +%s)
    local alert_id="${component}_${severity}_$(date +%s)"
    
    # Add to active alerts
    local temp_file=$(mktemp)
    jq --arg id "$alert_id" --arg comp "$component" --arg sev "$severity" --arg msg "$message" --argjson ts "$timestamp" \
       '.active_alerts += [{"id": $id, "component": $comp, "severity": $sev, "message": $msg, "timestamp": $ts}]' \
       "$ALERTS_FILE" > "$temp_file" 2>/dev/null || {
        echo "{\"active_alerts\": [{\"id\": \"$alert_id\", \"component\": \"$component\", \"severity\": \"$severity\", \"message\": \"$message\", \"timestamp\": $timestamp}], \"alert_history\": []}" > "$temp_file"
    }
    
    mv "$temp_file" "$ALERTS_FILE"
    
    log_warn "ALERT: [$severity] $component - $message"
    
    # Send notifications
    send_notifications "$component" "$severity" "$message"
}

# Clear resolved alerts
clear_alert() {
    local component="$1"
    local timestamp=$(date +%s)
    
    # Move active alerts to history and clear them
    local temp_file=$(mktemp)
    jq --arg comp "$component" --argjson ts "$timestamp" \
       '.alert_history += (.active_alerts | map(select(.component == $comp) | . + {"resolved_at": $ts})) | .active_alerts = (.active_alerts | map(select(.component != $comp)))' \
       "$ALERTS_FILE" > "$temp_file" 2>/dev/null || cp "$ALERTS_FILE" "$temp_file"
    
    mv "$temp_file" "$ALERTS_FILE"
    
    log_info "RESOLVED: $component alerts cleared"
}

# Send notifications
send_notifications() {
    local component="$1"
    local severity="$2"
    local message="$3"
    
    # Email notification
    if command -v mail >/dev/null 2>&1 && [[ -n "$ADMIN_EMAIL" ]]; then
        {
            echo "Subject: [2R-AT Alert] $severity - $component"
            echo "From: $FROM_EMAIL"
            echo "To: $ADMIN_EMAIL"
            echo ""
            echo "2R-AT Security Platform Alert"
            echo "=============================="
            echo ""
            echo "Component: $component"
            echo "Severity: $severity"
            echo "Message: $message"
            echo "Timestamp: $(date)"
            echo "Server: $(hostname)"
            echo ""
            echo "Please investigate immediately."
        } | mail -s "[2R-AT Alert] $severity - $component" "$ADMIN_EMAIL" 2>/dev/null || {
            log_error "Failed to send email notification"
        }
    fi
    
    # Slack notification
    if [[ -n "$SLACK_WEBHOOK" ]] && command -v curl >/dev/null 2>&1; then
        local color="warning"
        [[ "$severity" == "CRITICAL" ]] && color="danger"
        
        local payload=$(cat <<EOF
{
    "attachments": [
        {
            "color": "$color",
            "title": "2R-AT Alert: $component",
            "text": "$message",
            "fields": [
                {"title": "Severity", "value": "$severity", "short": true},
                {"title": "Server", "value": "$(hostname)", "short": true},
                {"title": "Time", "value": "$(date)", "short": false}
            ]
        }
    ]
}
EOF
        )
        
        curl -X POST -H 'Content-type: application/json' \
             --data "$payload" \
             "$SLACK_WEBHOOK" >/dev/null 2>&1 || {
            log_error "Failed to send Slack notification"
        }
    fi
}

# Generate health report
generate_health_report() {
    local overall_status="OK"
    local critical_issues=()
    local warning_issues=()
    local all_metrics=()
    
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}2R-AT Security Platform Health Report${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo "Generated: $(date)"
    echo "Server: $(hostname)"
    echo ""
    
    # Run all checks
    local checks=(
        "System Resources:check_system_resources"
        "Services:check_services"
        "Network:check_network"
        "API Health:check_api_health"
        "Database:check_database"
        "Logs:check_logs"
        "Security:check_security"
    )
    
    for check in "${checks[@]}"; do
        local name="${check%:*}"
        local func="${check#*:}"
        
        echo -n "Checking $name... "
        local result=$($func)
        local status="${result%%|*}"
        local temp="${result#*|}"
        local issues="${temp%|*}"
        local metrics="${result##*|}"
        
        case $status in
            "OK")
                echo -e "${GREEN}✓ OK${NC}"
                ;;
            "WARNING")
                echo -e "${YELLOW}⚠ WARNING${NC}"
                overall_status="WARNING"
                [[ -n "$issues" ]] && warning_issues+=("$name: $issues")
                ;;
            "CRITICAL")
                echo -e "${RED}✗ CRITICAL${NC}"
                overall_status="CRITICAL"
                [[ -n "$issues" ]] && critical_issues+=("$name: $issues")
                ;;
        esac
        
        # Show issues if any
        if [[ -n "$issues" && "$issues" != "${temp%|*}" ]]; then
            echo "    Issues: $issues"
        fi
        
        # Show metrics if any
        if [[ -n "$metrics" && "$metrics" != "$temp" ]]; then
            echo "    Metrics: $metrics"
            all_metrics+=("$name: $metrics")
        fi
        
        # Handle alerting
        if [[ "$status" == "CRITICAL" || "$status" == "WARNING" ]]; then
            create_alert "$name" "$status" "$issues"
        else
            clear_alert "$name"
        fi
    done
    
    echo ""
    echo -e "${PURPLE}Overall Status: ${NC}"
    case $overall_status in
        "OK")
            echo -e "${GREEN}✓ System is healthy${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}⚠ System has warnings${NC}"
            ;;
        "CRITICAL")
            echo -e "${RED}✗ System has critical issues${NC}"
            ;;
    esac
    
    # Show summary of issues
    if [[ ${#critical_issues[@]} -gt 0 ]]; then
        echo ""
        echo -e "${RED}Critical Issues:${NC}"
        for issue in "${critical_issues[@]}"; do
            echo -e "  ${RED}✗${NC} $issue"
        done
    fi
    
    if [[ ${#warning_issues[@]} -gt 0 ]]; then
        echo ""
        echo -e "${YELLOW}Warnings:${NC}"
        for issue in "${warning_issues[@]}"; do
            echo -e "  ${YELLOW}⚠${NC} $issue"
        done
    fi
    
    # Show system metrics
    if [[ ${#all_metrics[@]} -gt 0 ]]; then
        echo ""
        echo -e "${BLUE}System Metrics:${NC}"
        for metric in "${all_metrics[@]}"; do
            echo "  $metric"
        done
    fi
    
    echo ""
    echo -e "${CYAN}========================================${NC}"
    
    return $([ "$overall_status" = "OK" ] && echo 0 || echo 1)
}

# Performance analysis
show_performance_trends() {
    echo -e "${CYAN}Performance Trends (Last 24 Hours)${NC}"
    echo "================================="
    
    if command -v jq >/dev/null 2>&1 && [[ -f "$METRICS_FILE" ]]; then
        local current_time=$(date +%s)
        local day_ago=$((current_time - 86400))
        
        # CPU trends
        local avg_cpu=$(jq -r --argjson since "$day_ago" '.cpu | map(select(.timestamp >= $since)) | if length > 0 then (map(.value) | add / length) else 0 end' "$METRICS_FILE" 2>/dev/null || echo "0")
        echo "Average CPU Usage: ${avg_cpu}%"
        
        # Memory trends
        local avg_memory=$(jq -r --argjson since "$day_ago" '.memory | map(select(.timestamp >= $since)) | if length > 0 then (map(.value) | add / length) else 0 end' "$METRICS_FILE" 2>/dev/null || echo "0")
        echo "Average Memory Usage: ${avg_memory}%"
        
        # API response time trends
        local avg_response=$(jq -r --argjson since "$day_ago" '.api_response | map(select(.timestamp >= $since)) | if length > 0 then (map(.value) | add / length) else 0 end' "$METRICS_FILE" 2>/dev/null || echo "0")
        echo "Average API Response Time: ${avg_response}ms"
        
    else
        echo "Performance data not available"
    fi
    echo ""
}

# Show active alerts
show_active_alerts() {
    if command -v jq >/dev/null 2>&1 && [[ -f "$ALERTS_FILE" ]]; then
        local alert_count=$(jq -r '.active_alerts | length' "$ALERTS_FILE" 2>/dev/null || echo "0")
        
        if [[ $alert_count -gt 0 ]]; then
            echo -e "${RED}Active Alerts ($alert_count):${NC}"
            echo "==============="
            
            jq -r '.active_alerts[] | "\(.component) [\(.severity)] - \(.message) (Since: \(.timestamp | strftime("%Y-%m-%d %H:%M:%S")))"' "$ALERTS_FILE" 2>/dev/null || echo "Error reading alerts"
            echo ""
        fi
    fi
}

# Cleanup old data
cleanup_old_data() {
    local current_time=$(date +%s)
    local week_ago=$((current_time - 604800))  # 7 days
    
    # Clean old metrics
    if command -v jq >/dev/null 2>&1 && [[ -f "$METRICS_FILE" ]]; then
        local temp_file=$(mktemp)
        jq --argjson since "$week_ago" \
           'to_entries | map(.value = (.value | map(select(.timestamp >= $since)))) | from_entries' \
           "$METRICS_FILE" > "$temp_file" 2>/dev/null && mv "$temp_file" "$METRICS_FILE"
    fi
    
    # Clean old alert history
    if command -v jq >/dev/null 2>&1 && [[ -f "$ALERTS_FILE" ]]; then
        local temp_file=$(mktemp)
        jq --argjson since "$week_ago" \
           '.alert_history = (.alert_history | map(select(.timestamp >= $since)))' \
           "$ALERTS_FILE" > "$temp_file" 2>/dev/null && mv "$temp_file" "$ALERTS_FILE"
    fi
}

# Main execution
main() {
    local command="${1:-monitor}"
    
    # Ensure required directories exist
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Load configuration and initialize
    load_config
    init_state
    
    case $command in
        "monitor"|"check")
            log_info "Starting monitoring check"
            generate_health_report
            cleanup_old_data
            ;;
        "status")
            show_active_alerts
            show_performance_trends
            generate_health_report
            ;;
        "alerts")
            show_active_alerts
            ;;
        "trends"|"performance")
            show_performance_trends
            ;;
        "test-alert")
            create_alert "Test" "WARNING" "This is a test alert"
            echo "Test alert created"
            ;;
        "clear-alerts")
            echo '{"active_alerts": [], "alert_history": []}' > "$ALERTS_FILE"
            echo "All alerts cleared"
            ;;
        "cleanup")
            cleanup_old_data
            echo "Old data cleaned up"
            ;;
        "help"|"-h"|"--help")
            cat << EOF
2R-AT Advanced Monitoring Script

Usage: $0 [COMMAND]

Commands:
  monitor, check    Run full monitoring check (default)
  status           Show detailed system status
  alerts           Show active alerts only
  trends           Show performance trends
  test-alert       Create a test alert
  clear-alerts     Clear all active alerts
  cleanup          Clean up old monitoring data
  help             Show this help message

Configuration file: $CONFIG_FILE
Log file: $LOG_FILE

EOF
            ;;
        *)
            echo "Unknown command: $command"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Handle script termination
trap 'log_info "Monitoring script terminated"' EXIT

# Run main function
main "$@"