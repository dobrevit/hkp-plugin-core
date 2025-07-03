#!/bin/bash

# Test script to verify plugin loading
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PLUGIN_DIR="$PROJECT_ROOT/cmd/interpose/plugins"

echo "=== Plugin Dynamic Loading Test ==="
echo "Plugin directory: $PLUGIN_DIR"
echo

echo "Available plugins:"
ls -la "$PLUGIN_DIR"/*.so 2>/dev/null || echo "No plugins found"

echo
echo "Testing application startup with plugins..."
cd "$PROJECT_ROOT/cmd/interpose"

# Run for a short time to see plugin loading messages
timeout 3s go run . 2>&1 | grep -E "(Successfully loaded plugin|Failed to load plugin|plugin)" || true

echo
echo "Test completed!"