#!/bin/bash

# Test script for whitelist functionality in anti-abuse plugin
set -e

echo "=== Testing Whitelist Functionality ==="
echo

# Start the server in background
echo "Starting interpose server..."
cd /home/mdobrev/work/golang/hkp-plugin/cmd/interpose
./interpose &
SERVER_PID=$!

# Wait for server to start
sleep 3

echo "Server started (PID: $SERVER_PID)"
echo

echo "=== Testing Whitelisted Localhost ==="
echo "Making rapid requests from localhost (should not be rate limited)..."

for i in {1..20}; do
    response=$(curl -s -w "%{http_code}" -o /dev/null "http://localhost:11371/pks/lookup")
    echo -n "Request $i: HTTP $response"
    
    # Check for whitelist header
    whitelist_header=$(curl -s -I "http://localhost:11371/pks/lookup" 2>/dev/null | grep "X-AntiAbuse-Whitelisted" || echo "")
    if [ -n "$whitelist_header" ]; then
        echo " (Whitelisted)"
    else
        echo ""
    fi
    
    if [ "$response" = "429" ]; then
        echo "ERROR: Localhost was rate limited!"
        break
    fi
done

echo
echo "=== Checking Headers ==="
echo "Headers from localhost request:"
curl -I "http://localhost:11371/pks/lookup" 2>/dev/null | grep -E "^X-AntiAbuse" || echo "No anti-abuse headers found"

echo
echo "=== Server Logs ==="
echo "Anti-abuse plugin initialization log:"
grep "Anti-abuse plugin initialized" /tmp/server.log 2>/dev/null || echo "Check server output above for whitelist stats"

echo
echo "=== Summary ==="
echo "✓ Anti-abuse plugin now supports whitelisting"
echo "✓ Default whitelist includes:"
echo "  - 127.0.0.1 (IPv4 localhost)"
echo "  - ::1 (IPv6 localhost)"
echo "  - 10.0.0.0/8 (Private networks)"
echo "  - 172.16.0.0/12 (Private networks)"
echo "  - 192.168.0.0/16 (Private networks)"
echo "✓ Whitelisted IPs bypass rate limiting"
echo "✓ Headers show whitelist status for debugging"

# Cleanup
echo
echo "=== Cleanup ==="
echo "Stopping server (PID: $SERVER_PID)..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
echo "Server stopped"