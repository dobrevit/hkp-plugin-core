#!/bin/bash

# API Testing Script for HKP Plugin System
# This script tests all API endpoints using curl

set -e

# Configuration
BASE_URL=${BASE_URL:-"http://localhost:11371"}
VERBOSE=${VERBOSE:-false}

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Session variables
SESSION_ID=""
SESSION_COOKIE=""

# Helper functions
print_test() {
    echo -e "\n${BLUE}TEST: $1${NC}"
    ((TESTS_RUN++))
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    ((TESTS_PASSED++))
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
    ((TESTS_FAILED++))
}

print_info() {
    echo -e "${YELLOW}→ $1${NC}"
}

# Function to make HTTP request
make_request() {
    local method=$1
    local endpoint=$2
    local data=$3
    local expected_status=$4
    local description=$5
    
    print_test "$description"
    
    # Build curl command
    local curl_cmd="curl -s -w '\n%{http_code}' -X $method"
    
    if [ "$method" = "POST" ] || [ "$method" = "PUT" ]; then
        curl_cmd="$curl_cmd -H 'Content-Type: application/json'"
        if [ -n "$data" ]; then
            curl_cmd="$curl_cmd -d '$data'"
        fi
    fi
    
    if [ -n "$SESSION_COOKIE" ]; then
        curl_cmd="$curl_cmd -H 'Cookie: $SESSION_COOKIE'"
    fi
    
    curl_cmd="$curl_cmd $BASE_URL$endpoint"
    
    if [ "$VERBOSE" = true ]; then
        print_info "Request: $curl_cmd"
    fi
    
    # Execute request
    local response=$(eval $curl_cmd 2>/dev/null)
    local http_code=$(echo "$response" | tail -n 1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$VERBOSE" = true ]; then
        print_info "Response Code: $http_code"
        print_info "Response Body: $body"
    fi
    
    # Check status code
    if [ "$http_code" = "$expected_status" ]; then
        print_success "Got expected status: $http_code"
        echo "$body"
        return 0
    else
        print_error "Expected status $expected_status, got $http_code"
        echo "$body"
        return 1
    fi
}

# Test Core Endpoints
test_core_endpoints() {
    echo -e "\n${YELLOW}=== Testing Core Endpoints ===${NC}"
    
    # Test PKS lookup
    make_request "GET" "/pks/lookup?search=test@example.com" "" "200" "PKS Lookup"
    
    # Test PKS add (would need actual PGP key)
    local pgp_key='{"keytext":"-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----"}'
    make_request "POST" "/pks/add" "$pgp_key" "200" "PKS Add Key"
    
    # Test server stats
    make_request "GET" "/pks/stats" "" "200" "Server Statistics"
    
    # Test metrics
    make_request "GET" "/metrics" "" "200" "Prometheus Metrics"
}

# Test Zero Trust Plugin
test_zerotrust_plugin() {
    echo -e "\n${YELLOW}=== Testing Zero Trust Plugin ===${NC}"
    
    # Test ZTNA status (may require auth)
    local status_response=$(make_request "GET" "/ztna/status" "" "200" "ZTNA Status" 2>/dev/null || echo "Access denied - auth required")
    if [[ "$status_response" == *"Access denied"* ]]; then
        print_info "ZTNA Status requires authentication (Zero Trust policy active)"
    fi
    
    # Test login
    local login_data='{"username":"testuser","password":"demo-password-testuser"}'
    local login_response=$(make_request "POST" "/ztna/login" "$login_data" "200" "ZTNA Login")
    
    # Extract session ID if login successful
    if echo "$login_response" | grep -q "session_id"; then
        SESSION_ID=$(echo "$login_response" | grep -o '"session_id":"[^"]*"' | cut -d'"' -f4)
        SESSION_COOKIE="ztna-session=$SESSION_ID"
        print_info "Session ID: $SESSION_ID"
    fi
    
    # Test device registration (requires session)
    if [ -n "$SESSION_ID" ]; then
        local device_data='{
            "platform":"linux",
            "screen_resolution":"1920x1080",
            "timezone":"UTC",
            "plugins":["pdf","flash"],
            "fonts":["Arial","Times"]
        }'
        make_request "POST" "/ztna/device" "$device_data" "200" "ZTNA Device Registration"
    fi
    
    # Test MFA verification
    local verify_data='{"type":"totp","code":"123456-tes"}'
    make_request "POST" "/ztna/verify" "$verify_data" "200" "ZTNA MFA Verification"
    
    # Test logout
    make_request "POST" "/ztna/logout" "" "200" "ZTNA Logout"
    SESSION_COOKIE=""
}

# Test ML Abuse Plugin
test_mlabuse_plugin() {
    echo -e "\n${YELLOW}=== Testing ML Abuse Plugin ===${NC}"
    
    # Test ML status
    make_request "GET" "/api/ml/status" "" "200" "ML Abuse Status"
    
    # Test ML metrics
    make_request "GET" "/api/ml/metrics" "" "200" "ML Abuse Metrics"
    
    # Test ML analyze
    local analyze_data='{
        "request_data": {
            "method": "POST",
            "path": "/api/test",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "test content"
        },
        "context": {
            "ip": "192.168.1.100",
            "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'"
        }
    }'
    make_request "POST" "/api/ml/analyze" "$analyze_data" "200" "ML Abuse Analysis"
}

# Test Rate Limit Plugins
test_ratelimit_plugins() {
    echo -e "\n${YELLOW}=== Testing Rate Limit Plugins ===${NC}"
    
    # Test Threat Intel
    make_request "GET" "/ratelimit/threatintel/status" "" "200" "Threat Intel Status"
    
    local check_data='{"ip":"192.168.1.100"}'
    make_request "POST" "/ratelimit/threatintel/check" "$check_data" "200" "Threat Intel Check IP"
    
    local report_data='{"ip":"10.0.0.1","type":"scanner","details":{"behavior":"port_scan"}}'
    make_request "POST" "/ratelimit/threatintel/report" "$report_data" "200" "Threat Intel Report"
    
    # Test Tarpit
    make_request "GET" "/ratelimit/tarpit/status" "" "200" "Tarpit Status"
    make_request "GET" "/ratelimit/tarpit/connections" "" "200" "Tarpit Connections"
    
    # Test ML Rate Limit
    make_request "GET" "/ratelimit/ml/status" "" "200" "ML Rate Limit Status"
    make_request "GET" "/ratelimit/ml/patterns" "" "200" "ML Rate Limit Patterns"
}

# Test Honeypot Paths (with timeout)
test_honeypot_paths() {
    echo -e "\n${YELLOW}=== Testing Honeypot Paths (Tarpit) ===${NC}"
    
    local honeypot_paths=("/admin" "/wp-admin" "/.git" "/.env" "/phpmyadmin")
    
    for path in "${honeypot_paths[@]}"; do
        print_test "Honeypot path: $path"
        
        # Use timeout to avoid hanging
        local start_time=$(date +%s)
        timeout 3s curl -s -o /dev/null -w "%{http_code}" "$BASE_URL$path" > /tmp/honeypot_test 2>&1
        local exit_code=$?
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        if [ $exit_code -eq 124 ]; then
            print_success "Request timed out after ${duration}s (tarpit active)"
        else
            local status=$(cat /tmp/honeypot_test 2>/dev/null || echo "error")
            print_info "Got status $status after ${duration}s"
        fi
    done
    
    rm -f /tmp/honeypot_test
}

# Main test execution
main() {
    echo -e "${GREEN}HKP Plugin System API Test Suite${NC}"
    echo -e "Testing against: ${BLUE}$BASE_URL${NC}\n"
    
    # Check if server is running
    if ! curl -s -o /dev/null "$BASE_URL"; then
        print_error "Server is not responding at $BASE_URL"
        echo "Please start the server with: make run"
        exit 1
    fi
    
    # Run all tests
    test_core_endpoints
    test_zerotrust_plugin
    test_mlabuse_plugin
    test_ratelimit_plugins
    test_honeypot_paths
    
    # Print summary
    echo -e "\n${YELLOW}=== Test Summary ===${NC}"
    echo -e "Tests run:    $TESTS_RUN"
    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "\n${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "\n${RED}Some tests failed!${NC}"
        exit 1
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -u|--url)
            BASE_URL="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -v, --verbose    Show detailed request/response information"
            echo "  -u, --url URL    Base URL for API (default: http://localhost:8080)"
            echo "  -h, --help       Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run tests
main