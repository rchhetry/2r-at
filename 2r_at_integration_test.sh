#!/bin/bash
# ========================================
# 2R-AT Integration Testing Script
# Comprehensive testing of all platform components
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
API_BASE_URL="http://127.0.0.1:5000/api"
WEB_BASE_URL="http://127.0.0.1"
DATABASE_PATH="/var/lib/2r-at/scanner.db"
LOG_FILE="/var/log/2r-at/integration-test.log"
TEST_RESULTS_FILE="/tmp/2r-at-test-results.json"

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Test data
TEST_EMAIL="test-user-$(date +%s)@example.com"
TEST_PASSWORD="TestPassword123!"
TEST_NAME="Integration Test User"
TEST_TARGET="httpbin.org"
ACCESS_TOKEN=""

print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
  ____  ____       _  _____   ___       _                       _   _             
 |___ \|  _ \     / \|_   _| |_ _|_ __ | |_ ___  __ _ _ __ __ _| |_(_) ___  _ __  
   __) | |_) |   / _ \ | |    | || '_ \| __/ _ \/ _` | '__/ _` | __| |/ _ \| '_ \ 
  / __/|  _ <   / ___ \| |    | || | | | ||  __/ (_| | | | (_| | |_| | (_) | | | |
 |_____|_| \_\ /_/   \_\_|   |___|_| |_|\__\___|\__, |_|  \__,_|\__|_|\___/|_| |_|
                                                |___/                            
 _____         _   _             
|_   _|__  ___| |_(_)_ __   __ _ 
  | |/ _ \/ __| __| | '_ \ / _` |
  | |  __/\__ \ |_| | | | | (_| |
  |_|\___||___/\__|_|_| |_|\__, |
                           |___/ 
EOF
    echo -e "${NC}"
}

log_test() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" >> "$LOG_FILE"
}

print_test_header() {
    local test_name="$1"
    echo -e "\n${BLUE}=== ${test_name} ===${NC}"
    log_test "Starting test: $test_name"
}

print_test_result() {
    local test_name="$1"
    local result="$2"
    local message="${3:-}"
    
    ((TOTAL_TESTS++))
    
    case $result in
        "PASS")
            echo -e "${GREEN}✓ PASS${NC}: $test_name"
            [[ -n "$message" ]] && echo "  $message"
            ((PASSED_TESTS++))
            log_test "PASS: $test_name - $message"
            ;;
        "FAIL")
            echo -e "${RED}✗ FAIL${NC}: $test_name"
            [[ -n "$message" ]] && echo -e "  ${RED}$message${NC}"
            ((FAILED_TESTS++))
            log_test "FAIL: $test_name - $message"
            ;;
        "SKIP")
            echo -e "${YELLOW}⚠ SKIP${NC}: $test_name"
            [[ -n "$message" ]] && echo -e "  ${YELLOW}$message${NC}"
            ((SKIPPED_TESTS++))
            log_test "SKIP: $test_name - $message"
            ;;
    esac
}

# HTTP request helper
make_request() {
    local method="$1"
    local url="$2"
    local data="${3:-}"
    local auth_header="${4:-}"
    
    local curl_opts=(-s -w "%{http_code}" -o /tmp/response_body.json)
    
    if [[ -n "$auth_header" ]]; then
        curl_opts+=(-H "Authorization: Bearer $auth_header")
    fi
    
    if [[ -n "$data" ]]; then
        curl_opts+=(-H "Content-Type: application/json" -d "$data")
    fi
    
    curl "${curl_opts[@]}" -X "$method" "$url"
}

# Test system prerequisites
test_prerequisites() {
    print_test_header "System Prerequisites"
    
    # Test 1: Check if all required services are running
    local services=("httpd" "redis" "firewalld")
    local all_services_running=true
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            print_test_result "Service $service" "PASS" "Service is running"
        else
            print_test_result "Service $service" "FAIL" "Service is not running"
            all_services_running=false
        fi
    done
    
    # Test 2: Check 2R-AT scanner service
    if systemctl list-unit-files | grep -q "2r-at-scanner.service"; then
        if systemctl is-active --quiet "2r-at-scanner"; then
            print_test_result "2R-AT Scanner Service" "PASS" "Service is running"
        else
            print_test_result "2R-AT Scanner Service" "FAIL" "Service is not running"
        fi
    else
        print_test_result "2R-AT Scanner Service" "SKIP" "Service not installed"
    fi
    
    # Test 3: Check database accessibility
    if [[ -f "$DATABASE_PATH" ]] && sqlite3 "$DATABASE_PATH" "SELECT 1;" >/dev/null 2>&1; then
        print_test_result "Database Access" "PASS" "Database is accessible"
    else
        print_test_result "Database Access" "FAIL" "Database is not accessible"
    fi
    
    # Test 4: Check Nuclei installation
    if command -v nuclei >/dev/null 2>&1; then
        local nuclei_version=$(nuclei -version 2>/dev/null | head -1 || echo "unknown")
        print_test_result "Nuclei Scanner" "PASS" "Version: $nuclei_version"
    else
        print_test_result "Nuclei Scanner" "FAIL" "Nuclei not found in PATH"
    fi
    
    # Test 5: Check network connectivity
    if curl -sf --max-time 10 http://127.0.0.1 >/dev/null 2>&1; then
        print_test_result "HTTP Connectivity" "PASS" "Apache is responding"
    else
        print_test_result "HTTP Connectivity" "FAIL" "Apache is not responding"
    fi
    
    # Test 6: Check Redis connectivity
    if redis-cli ping >/dev/null 2>&1; then
        print_test_result "Redis Connectivity" "PASS" "Redis is responding"
    else
        print_test_result "Redis Connectivity" "FAIL" "Redis is not responding"
    fi
}

# Test API endpoints
test_api_endpoints() {
    print_test_header "API Endpoints"
    
    # Test 1: Health check endpoint
    local health_status=$(make_request "GET" "$API_BASE_URL/health")
    if [[ "$health_status" == "200" ]]; then
        local health_data=$(cat /tmp/response_body.json)
        if echo "$health_data" | grep -q '"status": "healthy"'; then
            print_test_result "Health Check Endpoint" "PASS" "API is healthy"
        else
            print_test_result "Health Check Endpoint" "FAIL" "API reports unhealthy status"
        fi
    else
        print_test_result "Health Check Endpoint" "FAIL" "HTTP status: $health_status"
    fi
    
    # Test 2: Invalid endpoint returns 404
    local invalid_status=$(make_request "GET" "$API_BASE_URL/nonexistent")
    if [[ "$invalid_status" == "404" ]]; then
        print_test_result "404 Error Handling" "PASS" "Correctly returns 404 for invalid endpoints"
    else
        print_test_result "404 Error Handling" "FAIL" "Expected 404, got $invalid_status"
    fi
    
    # Test 3: Unauthenticated access to protected endpoints
    local protected_status=$(make_request "GET" "$API_BASE_URL/scans")
    if [[ "$protected_status" == "401" || "$protected_status" == "403" || "$protected_status" == "422" ]]; then
        print_test_result "Authentication Protection" "PASS" "Protected endpoints require authentication"
    else
        print_test_result "Authentication Protection" "FAIL" "Protected endpoint accessible without auth (status: $protected_status)"
    fi
}

# Test user authentication
test_authentication() {
    print_test_header "User Authentication"
    
    # Test 1: User registration
    local register_data=$(cat <<EOF
{
    "email": "$TEST_EMAIL",
    "name": "$TEST_NAME",
    "password": "$TEST_PASSWORD",
    "company": "Test Company"
}
EOF
    )
    
    local register_status=$(make_request "POST" "$API_BASE_URL/auth/register" "$register_data")
    if [[ "$register_status" == "201" ]]; then
        local register_response=$(cat /tmp/response_body.json)
        if echo "$register_response" | grep -q '"access_token"'; then
            ACCESS_TOKEN=$(echo "$register_response" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null || echo "")
            if [[ -n "$ACCESS_TOKEN" ]]; then
                print_test_result "User Registration" "PASS" "User registered successfully with token"
            else
                print_test_result "User Registration" "FAIL" "Registration successful but no token returned"
            fi
        else
            print_test_result "User Registration" "FAIL" "Registration successful but response malformed"
        fi
    else
        print_test_result "User Registration" "FAIL" "HTTP status: $register_status"
        return 1
    fi
    
    # Test 2: Duplicate user registration
    local duplicate_status=$(make_request "POST" "$API_BASE_URL/auth/register" "$register_data")
    if [[ "$duplicate_status" == "409" ]]; then
        print_test_result "Duplicate User Prevention" "PASS" "Correctly prevents duplicate user registration"
    else
        print_test_result "Duplicate User Prevention" "FAIL" "Expected 409, got $duplicate_status"
    fi
    
    # Test 3: User login
    local login_data=$(cat <<EOF
{
    "email": "$TEST_EMAIL",
    "password": "$TEST_PASSWORD"
}
EOF
    )
    
    local login_status=$(make_request "POST" "$API_BASE_URL/auth/login" "$login_data")
    if [[ "$login_status" == "200" ]]; then
        local login_response=$(cat /tmp/response_body.json)
        if echo "$login_response" | grep -q '"access_token"'; then
            print_test_result "User Login" "PASS" "User login successful"
        else
            print_test_result "User Login" "FAIL" "Login successful but no token returned"
        fi
    else
        print_test_result "User Login" "FAIL" "HTTP status: $login_status"
    fi
    
    # Test 4: Invalid login credentials
    local invalid_login_data=$(cat <<EOF
{
    "email": "$TEST_EMAIL",
    "password": "WrongPassword"
}
EOF
    )
    
    local invalid_login_status=$(make_request "POST" "$API_BASE_URL/auth/login" "$invalid_login_data")
    if [[ "$invalid_login_status" == "401" ]]; then
        print_test_result "Invalid Credentials Handling" "PASS" "Correctly rejects invalid credentials"
    else
        print_test_result "Invalid Credentials Handling" "FAIL" "Expected 401, got $invalid_login_status"
    fi
}

# Test authenticated endpoints
test_authenticated_endpoints() {
    print_test_header "Authenticated Endpoints"
    
    if [[ -z "$ACCESS_TOKEN" ]]; then
        print_test_result "Authenticated Endpoints" "SKIP" "No access token available"
        return 1
    fi
    
    # Test 1: Get user statistics
    local stats_status=$(make_request "GET" "$API_BASE_URL/stats" "" "$ACCESS_TOKEN")
    if [[ "$stats_status" == "200" ]]; then
        local stats_response=$(cat /tmp/response_body.json)
        if echo "$stats_response" | grep -q '"scans"' && echo "$stats_response" | grep -q '"quota"'; then
            print_test_result "User Statistics" "PASS" "Statistics endpoint working"
        else
            print_test_result "User Statistics" "FAIL" "Statistics response malformed"
        fi
    else
        print_test_result "User Statistics" "FAIL" "HTTP status: $stats_status"
    fi
    
    # Test 2: Get user scans (should be empty initially)
    local scans_status=$(make_request "GET" "$API_BASE_URL/scans" "" "$ACCESS_TOKEN")
    if [[ "$scans_status" == "200" ]]; then
        local scans_response=$(cat /tmp/response_body.json)
        if echo "$scans_response" | grep -q '"scans"'; then
            print_test_result "User Scans List" "PASS" "Scans endpoint working"
        else
            print_test_result "User Scans List" "FAIL" "Scans response malformed"
        fi
    else
        print_test_result "User Scans List" "FAIL" "HTTP status: $scans_status"
    fi
    
    # Test 3: Rate limiting (make rapid requests)
    local rate_limit_exceeded=false
    for i in {1..15}; do
        local rapid_status=$(make_request "GET" "$API_BASE_URL/stats" "" "$ACCESS_TOKEN")
        if [[ "$rapid_status" == "429" ]]; then
            rate_limit_exceeded=true
            break
        fi
        sleep 0.1
    done
    
    if [[ "$rate_limit_exceeded" == "true" ]]; then
        print_test_result "Rate Limiting" "PASS" "Rate limiting is working"
    else
        print_test_result "Rate Limiting" "SKIP" "Rate limiting not triggered in test"
    fi
}

# Test scan functionality
test_scan_functionality() {
    print_test_header "Scan Functionality"
    
    if [[ -z "$ACCESS_TOKEN" ]]; then
        print_test_result "Scan Functionality" "SKIP" "No access token available"
        return 1
    fi
    
    # Test 1: Create a scan
    local scan_data=$(cat <<EOF
{
    "target": "$TEST_TARGET",
    "scan_name": "Integration Test Scan",
    "options": {
        "severity": "low"
    }
}
EOF
    )
    
    local scan_create_status=$(make_request "POST" "$API_BASE_URL/scans" "$scan_data" "$ACCESS_TOKEN")
    if [[ "$scan_create_status" == "201" ]]; then
        local scan_response=$(cat /tmp/response_body.json)
        if echo "$scan_response" | grep -q '"scan_id"'; then
            local SCAN_ID=$(echo "$scan_response" | python3 -c "import sys, json; print(json.load(sys.stdin)['scan_id'])" 2>/dev/null || echo "")
            if [[ -n "$SCAN_ID" ]]; then
                print_test_result "Scan Creation" "PASS" "Scan created with ID: $SCAN_ID"
                
                # Test 2: Get scan details
                sleep 2  # Wait a moment for scan to be processed
                local scan_detail_status=$(make_request "GET" "$API_BASE_URL/scans/$SCAN_ID" "" "$ACCESS_TOKEN")
                if [[ "$scan_detail_status" == "200" ]]; then
                    local scan_detail_response=$(cat /tmp/response_body.json)
                    if echo "$scan_detail_response" | grep -q '"scan"'; then
                        print_test_result "Scan Details Retrieval" "PASS" "Scan details retrieved successfully"
                    else
                        print_test_result "Scan Details Retrieval" "FAIL" "Scan details response malformed"
                    fi
                else
                    print_test_result "Scan Details Retrieval" "FAIL" "HTTP status: $scan_detail_status"
                fi
                
                # Test 3: Wait for scan completion (with timeout)
                local scan_completed=false
                local timeout_count=0
                local max_timeout=60  # 5 minutes maximum
                
                while [[ $timeout_count -lt $max_timeout ]]; do
                    local status_check=$(make_request "GET" "$API_BASE_URL/scans/$SCAN_ID" "" "$ACCESS_TOKEN")
                    if [[ "$status_check" == "200" ]]; then
                        local status_response=$(cat /tmp/response_body.json)
                        local scan_status=$(echo "$status_response" | python3 -c "import sys, json; print(json.load(sys.stdin)['scan']['status'])" 2>/dev/null || echo "unknown")
                        
                        if [[ "$scan_status" == "completed" ]]; then
                            scan_completed=true
                            print_test_result "Scan Execution" "PASS" "Scan completed successfully"
                            break
                        elif [[ "$scan_status" == "failed" ]]; then
                            print_test_result "Scan Execution" "FAIL" "Scan failed during execution"
                            break
                        fi
                    fi
                    
                    sleep 5
                    ((timeout_count++))
                done
                
                if [[ "$scan_completed" != "true" && $timeout_count -ge $max_timeout ]]; then
                    print_test_result "Scan Execution" "FAIL" "Scan did not complete within timeout period"
                fi
                
            else
                print_test_result "Scan Creation" "FAIL" "Scan created but no ID returned"
            fi
        else
            print_test_result "Scan Creation" "FAIL" "Scan creation response malformed"
        fi
    else
        print_test_result "Scan Creation" "FAIL" "HTTP status: $scan_create_status"
    fi
    
    # Test 4: Invalid scan target
    local invalid_scan_data=$(cat <<EOF
{
    "target": "",
    "scan_name": "Invalid Scan"
}
EOF
    )
    
    local invalid_scan_status=$(make_request "POST" "$API_BASE_URL/scans" "$invalid_scan_data" "$ACCESS_TOKEN")
    if [[ "$invalid_scan_status" == "400" ]]; then
        print_test_result "Invalid Scan Validation" "PASS" "Correctly rejects invalid scan requests"
    else
        print_test_result "Invalid Scan Validation" "FAIL" "Expected 400, got $invalid_scan_status"
    fi
}

# Test database operations
test_database_operations() {
    print_test_header "Database Operations"
    
    # Test 1: Database schema version
    if [[ -f "$DATABASE_PATH" ]]; then
        local schema_version=$(sqlite3 "$DATABASE_PATH" "PRAGMA user_version;" 2>/dev/null || echo "0")
        if [[ "$schema_version" -gt 0 ]]; then
            print_test_result "Database Schema" "PASS" "Schema version: $schema_version"
        else
            print_test_result "Database Schema" "FAIL" "Invalid schema version: $schema_version"
        fi
    else
        print_test_result "Database Schema" "FAIL" "Database file not found"
    fi
    
    # Test 2: Database integrity
    if sqlite3 "$DATABASE_PATH" "PRAGMA integrity_check;" 2>/dev/null | grep -q "ok"; then
        print_test_result "Database Integrity" "PASS" "Database integrity check passed"
    else
        print_test_result "Database Integrity" "FAIL" "Database integrity check failed"
    fi
    
    # Test 3: Test user exists in database
    local user_count=$(sqlite3 "$DATABASE_PATH" "SELECT COUNT(*) FROM users WHERE email = '$TEST_EMAIL';" 2>/dev/null || echo "0")
    if [[ "$user_count" == "1" ]]; then
        print_test_result "Test User in Database" "PASS" "Test user found in database"
    else
        print_test_result "Test User in Database" "FAIL" "Test user not found in database (count: $user_count)"
    fi
    
    # Test 4: Database tables exist
    local required_tables=("users" "scans" "user_stats")
    local missing_tables=()
    
    for table in "${required_tables[@]}"; do
        if ! sqlite3 "$DATABASE_PATH" ".tables" 2>/dev/null | grep -q "$table"; then
            missing_tables+=("$table")
        fi
    done
    
    if [[ ${#missing_tables[@]} -eq 0 ]]; then
        print_test_result "Database Tables" "PASS" "All required tables exist"
    else
        print_test_result "Database Tables" "FAIL" "Missing tables: ${missing_tables[*]}"
    fi
}

# Test web interface
test_web_interface() {
    print_test_header "Web Interface"
    
    # Test 1: Main page loads
    local main_page_status=$(curl -s -w "%{http_code}" -o /dev/null "$WEB_BASE_URL")
    if [[ "$main_page_status" == "200" ]]; then
        print_test_result "Main Page Load" "PASS" "Main page loads successfully"
    else
        print_test_result "Main Page Load" "FAIL" "HTTP status: $main_page_status"
    fi
    
    # Test 2: Static assets load
    local css_status=$(curl -s -w "%{http_code}" -o /dev/null "$WEB_BASE_URL/style.css" 2>/dev/null || echo "404")
    local js_status=$(curl -s -w "%{http_code}" -o /dev/null "$WEB_BASE_URL/script.js" 2>/dev/null || echo "404")
    
    # Note: These might not exist as separate files in single-file HTML implementation
    if [[ "$css_status" == "200" || "$js_status" == "200" ]]; then
        print_test_result "Static Assets" "PASS" "Static assets available"
    else
        print_test_result "Static Assets" "SKIP" "No separate static assets (inline implementation)"
    fi
    
    # Test 3: HTTPS redirect (if configured)
    local https_status=$(curl -s -w "%{http_code}" -o /dev/null "https://127.0.0.1" 2>/dev/null || echo "000")
    if [[ "$https_status" == "200" ]]; then
        print_test_result "HTTPS Configuration" "PASS" "HTTPS is working"
    else
        print_test_result "HTTPS Configuration" "SKIP" "HTTPS not configured (expected for development)"
    fi
}

# Test security features
test_security_features() {
    print_test_header "Security Features"
    
    # Test 1: SQL injection protection
    local sql_injection_data=$(cat <<EOF
{
    "email": "test'; DROP TABLE users; --",
    "password": "password"
}
EOF
    )
    
    local sql_injection_status=$(make_request "POST" "$API_BASE_URL/auth/login" "$sql_injection_data")
    if [[ "$sql_injection_status" == "401" || "$sql_injection_status" == "400" ]]; then
        print_test_result "SQL Injection Protection" "PASS" "SQL injection attempt blocked"
    else
        print_test_result "SQL Injection Protection" "FAIL" "Potential SQL injection vulnerability"
    fi
    
    # Test 2: XSS protection in API responses
    local xss_scan_data=$(cat <<EOF
{
    "target": "<script>alert('xss')</script>",
    "scan_name": "<img src=x onerror=alert('xss')>"
}
EOF
    )
    
    if [[ -n "$ACCESS_TOKEN" ]]; then
        local xss_status=$(make_request "POST" "$API_BASE_URL/scans" "$xss_scan_data" "$ACCESS_TOKEN")
        if [[ "$xss_status" == "400" ]]; then
            print_test_result "XSS Protection" "PASS" "XSS attempt in input rejected"
        else
            # Check if response is properly escaped
            local xss_response=$(cat /tmp/response_body.json)
            if echo "$xss_response" | grep -q "<script>" || echo "$xss_response" | grep -q "onerror="; then
                print_test_result "XSS Protection" "FAIL" "Unescaped script content in response"
            else
                print_test_result "XSS Protection" "PASS" "Input properly sanitized"
            fi
        fi
    else
        print_test_result "XSS Protection" "SKIP" "No access token for testing"
    fi
    
    # Test 3: Security headers
    local headers_response=$(curl -sI "$WEB_BASE_URL" 2>/dev/null || echo "")
    local security_headers_found=0
    
    if echo "$headers_response" | grep -qi "x-frame-options"; then
        ((security_headers_found++))
    fi
    if echo "$headers_response" | grep -qi "x-content-type-options"; then
        ((security_headers_found++))
    fi
    if echo "$headers_response" | grep -qi "x-xss-protection"; then
        ((security_headers_found++))
    fi
    
    if [[ $security_headers_found -gt 0 ]]; then
        print_test_result "Security Headers" "PASS" "Found $security_headers_found security headers"
    else
        print_test_result "Security Headers" "SKIP" "No security headers detected"
    fi
}

# Cleanup test data
cleanup_test_data() {
    print_test_header "Test Cleanup"
    
    # Remove test user from database
    if [[ -f "$DATABASE_PATH" ]]; then
        local deleted_users=$(sqlite3 "$DATABASE_PATH" "DELETE FROM users WHERE email = '$TEST_EMAIL'; SELECT changes();" 2>/dev/null || echo "0")
        if [[ "$deleted_users" == "1" ]]; then
            print_test_result "Test User Cleanup" "PASS" "Test user removed from database"
        else
            print_test_result "Test User Cleanup" "SKIP" "Test user not found for cleanup"
        fi
        
        # Remove any test scans
        local deleted_scans=$(sqlite3 "$DATABASE_PATH" "DELETE FROM scans WHERE target = '$TEST_TARGET' AND scan_name LIKE '%Integration Test%'; SELECT changes();" 2>/dev/null || echo "0")
        if [[ "$deleted_scans" -gt 0 ]]; then
            print_test_result "Test Scans Cleanup" "PASS" "Removed $deleted_scans test scans"
        else
            print_test_result "Test Scans Cleanup" "SKIP" "No test scans to clean up"
        fi
    fi
    
    # Clean up temporary files
    rm -f /tmp/response_body.json /tmp/2r-at-test-*.json
    print_test_result "Temporary Files Cleanup" "PASS" "Temporary files cleaned up"
}

# Generate test report
generate_test_report() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local success_rate=0
    
    if [[ $TOTAL_TESTS -gt 0 ]]; then
        success_rate=$(echo "scale=2; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l 2>/dev/null || echo "0")
    fi
    
    # Generate JSON report
    cat > "$TEST_RESULTS_FILE" << EOF
{
    "test_run": {
        "timestamp": "$timestamp",
        "total_tests": $TOTAL_TESTS,
        "passed_tests": $PASSED_TESTS,
        "failed_tests": $FAILED_TESTS,
        "skipped_tests": $SKIPPED_TESTS,
        "success_rate": $success_rate
    },
    "environment": {
        "hostname": "$(hostname)",
        "user": "$(whoami)",
        "api_base_url": "$API_BASE_URL",
        "web_base_url": "$WEB_BASE_URL",
        "database_path": "$DATABASE_PATH"
    }
}
EOF
    
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}2R-AT Integration Test Results${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
    echo "Test Run: $timestamp"
    echo "Server: $(hostname)"
    echo ""
    echo -e "${BLUE}Test Summary:${NC}"
    echo "  Total Tests: $TOTAL_TESTS"
    echo -e "  ${GREEN}Passed: $PASSED_TESTS${NC}"
    echo -e "  ${RED}Failed: $FAILED_TESTS${NC}"
    echo -e "  ${YELLOW}Skipped: $SKIPPED_TESTS${NC}"
    echo "  Success Rate: ${success_rate}%"
    echo ""
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo -e "${GREEN}🎉 All tests passed! The 2R-AT platform is working correctly.${NC}"
        echo ""
        echo -e "${BLUE}Next Steps:${NC}"
        echo "1. Configure SSL certificates for production use"
        echo "2. Set up monitoring and alerting"
        echo "3. Configure backup schedules"
        echo "4. Review security settings"
        echo "5. Create admin user accounts"
    else
        echo -e "${RED}⚠ Some tests failed. Please review the failures above.${NC}"
        echo ""
        echo -e "${YELLOW}Troubleshooting:${NC}"
        echo "1. Check service status: systemctl status httpd redis 2r-at-scanner"
        echo "2. Review logs: journalctl -u 2r-at-scanner -f"
        echo "3. Run health check: /usr/local/bin/2r-at-advanced-monitor.sh"
        echo "4. Check database: /usr/local/bin/2r-at-database-manager.sh check"
    fi
    
    echo ""
    echo "Test Results: $TEST_RESULTS_FILE"
    echo "Test Log: $LOG_FILE"
    echo -e "${CYAN}========================================${NC}"
    
    return $FAILED_TESTS
}

# Main execution
main() {
    local test_suite="${1:-all}"
    
    print_banner
    echo "Starting 2R-AT Integration Testing..."
    echo "Test Suite: $test_suite"
    echo ""
    
    # Initialize logging
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "Integration test started at $(date)" > "$LOG_FILE"
    
    # Run test suites
    case $test_suite in
        "all")
            test_prerequisites
            test_api_endpoints
            test_authentication
            test_authenticated_endpoints
            test_scan_functionality
            test_database_operations
            test_web_interface
            test_security_features
            cleanup_test_data
            ;;
        "quick")
            test_prerequisites
            test_api_endpoints
            test_authentication
            ;;
        "api")
            test_api_endpoints
            test_authentication
            test_authenticated_endpoints
            ;;
        "scan")
            test_authentication
            test_scan_functionality
            ;;
        "security")
            test_security_features
            ;;
        "database")
            test_database_operations
            ;;
        "web")
            test_web_interface
            ;;
        "prerequisites")
            test_prerequisites
            ;;
        *)
            echo "Unknown test suite: $test_suite"
            echo "Available suites: all, quick, api, scan, security, database, web, prerequisites"
            exit 1
            ;;
    esac
    
    # Generate final report
    generate_test_report
}

# Handle script termination
trap 'echo "Test interrupted"; cleanup_test_data; exit 1' INT TERM

# Run main function
main "$@"