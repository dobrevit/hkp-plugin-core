#!/bin/bash

# Test runner script for HKP Plugin System
# This script runs all tests including unit tests and integration tests

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration
TEST_TIMEOUT="10m"
VERBOSE=${VERBOSE:-false}
COVERAGE=${COVERAGE:-false}

# Print colored output
print_info() {
    echo -e "${YELLOW}→ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Function to run tests for a specific package
run_package_tests() {
    local package=$1
    local name=$2
    
    print_info "Testing $name ($package)"
    
    if [ "$COVERAGE" = true ]; then
        go test -timeout $TEST_TIMEOUT -coverprofile="coverage-$name.out" $package
    else
        if [ "$VERBOSE" = true ]; then
            go test -v -timeout $TEST_TIMEOUT $package
        else
            go test -timeout $TEST_TIMEOUT $package
        fi
    fi
    
    if [ $? -eq 0 ]; then
        print_success "$name tests passed"
    else
        print_error "$name tests failed"
        exit 1
    fi
}

# Main test execution
main() {
    print_info "Starting HKP Plugin System Tests"
    echo ""
    
    # Check if we're in the project root
    if [ ! -f "go.mod" ]; then
        print_error "Please run this script from the project root directory"
        exit 1
    fi
    
    # Clean test cache
    print_info "Cleaning test cache"
    go clean -testcache
    
    # Download dependencies
    print_info "Downloading dependencies"
    go mod download
    
    echo ""
    print_info "Running Unit Tests"
    echo "=================="
    
    # Unit tests for each plugin
    run_package_tests "./src/plugins/antiabuse/..." "Anti-Abuse Plugin"
    run_package_tests "./src/plugins/mlabuse/..." "ML Abuse Plugin"
    run_package_tests "./src/plugins/ratelimit-geo/..." "Rate Limit Geo Plugin"
    run_package_tests "./src/plugins/ratelimit-ml/..." "Rate Limit ML Plugin"
    run_package_tests "./src/plugins/ratelimit-tarpit/..." "Rate Limit Tarpit Plugin"
    run_package_tests "./src/plugins/ratelimit-threat/..." "Rate Limit Threat Plugin"
    run_package_tests "./src/plugins/zerotrust/..." "Zero Trust Plugin"
    
    # Core package tests
    run_package_tests "./pkg/..." "Core Packages"
    run_package_tests "./cmd/interpose/..." "Interpose Application"
    
    echo ""
    print_info "Running Integration Tests"
    echo "========================"
    
    # Build plugins first
    print_info "Building plugins for integration tests"
    make plugins > /dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        print_error "Failed to build plugins"
        exit 1
    fi
    
    # Run integration tests
    run_package_tests "./tests/..." "Integration Tests"
    
    # Generate coverage report if requested
    if [ "$COVERAGE" = true ]; then
        echo ""
        print_info "Generating coverage report"
        
        # Merge coverage files
        echo "mode: set" > coverage-all.out
        for f in coverage-*.out; do
            if [ -f "$f" ]; then
                tail -n +2 "$f" >> coverage-all.out
            fi
        done
        
        # Generate HTML report
        go tool cover -html=coverage-all.out -o coverage.html
        print_success "Coverage report generated: coverage.html"
        
        # Show coverage summary
        go tool cover -func=coverage-all.out | grep total
        
        # Clean up individual coverage files
        rm -f coverage-*.out
    fi
    
    echo ""
    print_success "All tests passed!"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -c|--coverage)
            COVERAGE=true
            shift
            ;;
        -t|--timeout)
            TEST_TIMEOUT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -v, --verbose    Run tests in verbose mode"
            echo "  -c, --coverage   Generate coverage report"
            echo "  -t, --timeout    Test timeout (default: 10m)"
            echo "  -h, --help       Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run tests
main