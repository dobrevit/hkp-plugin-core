#!/bin/bash

# Build script for dynamic plugins
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PLUGIN_OUTPUT_DIR="$PROJECT_ROOT/cmd/interpose/plugins"

echo "Building plugins..."
echo "Project root: $PROJECT_ROOT"
echo "Plugin output directory: $PLUGIN_OUTPUT_DIR"

# Ensure output directory exists
mkdir -p "$PLUGIN_OUTPUT_DIR"

# Build geo plugin
echo "Building ratelimit-geo plugin..."
cd "$PROJECT_ROOT/src/plugins/ratelimit-geo"
go build -buildmode=plugin -o "$PLUGIN_OUTPUT_DIR/ratelimit-geo.so" .
echo "Built: $PLUGIN_OUTPUT_DIR/ratelimit-geo.so"

# Build tarpit plugin  
echo "Building ratelimit-tarpit plugin..."
cd "$PROJECT_ROOT/src/plugins/ratelimit-tarpit"
timeout 30s go build -buildmode=plugin -o "$PLUGIN_OUTPUT_DIR/ratelimit-tarpit.so" . || echo "Tarpit plugin build failed or timed out"
if [ -f "$PLUGIN_OUTPUT_DIR/ratelimit-tarpit.so" ]; then
    echo "Built: $PLUGIN_OUTPUT_DIR/ratelimit-tarpit.so"
else
    echo "Warning: ratelimit-tarpit.so was not created"
fi

# Build threat intel plugin
echo "Building ratelimit-threat plugin..."
cd "$PROJECT_ROOT/src/plugins/ratelimit-threat"
go build -buildmode=plugin -o "$PLUGIN_OUTPUT_DIR/ratelimit-threat.so" .
echo "Built: $PLUGIN_OUTPUT_DIR/ratelimit-threat.so"

# Build ML plugin
echo "Building ratelimit-ml plugin..."
cd "$PROJECT_ROOT/src/plugins/ratelimit-ml"
timeout 30s go build -buildmode=plugin -o "$PLUGIN_OUTPUT_DIR/ratelimit-ml.so" . || echo "ML plugin build failed or timed out"
if [ -f "$PLUGIN_OUTPUT_DIR/ratelimit-ml.so" ]; then
    echo "Built: $PLUGIN_OUTPUT_DIR/ratelimit-ml.so"
else
    echo "Warning: ratelimit-ml.so was not created"
fi

# Build antiabuse plugin
echo "Building antiabuse plugin..."
cd "$PROJECT_ROOT/src/plugins/antiabuse"
go build -buildmode=plugin -o "$PLUGIN_OUTPUT_DIR/antiabuse.so" .
echo "Built: $PLUGIN_OUTPUT_DIR/antiabuse.so"

# Build mlabuse plugin
echo "Building mlabuse plugin..."
cd "$PROJECT_ROOT/src/plugins/mlabuse"
timeout 30s go build -buildmode=plugin -o "$PLUGIN_OUTPUT_DIR/mlabuse.so" . || echo "MLAbuse plugin build failed or timed out"
if [ -f "$PLUGIN_OUTPUT_DIR/mlabuse.so" ]; then
    echo "Built: $PLUGIN_OUTPUT_DIR/mlabuse.so"
else
    echo "Warning: mlabuse.so was not created"
fi

# Build zerotrust plugin
echo "Building zerotrust plugin..."
cd "$PROJECT_ROOT/src/plugins/zerotrust"
timeout 30s go build -buildmode=plugin -o "$PLUGIN_OUTPUT_DIR/zerotrust.so" . || echo "ZeroTrust plugin build failed or timed out"
if [ -f "$PLUGIN_OUTPUT_DIR/zerotrust.so" ]; then
    echo "Built: $PLUGIN_OUTPUT_DIR/zerotrust.so"
else
    echo "Warning: zerotrust.so was not created"
fi

echo "All plugins build process completed!"
echo "Plugin files:"
ls -la "$PLUGIN_OUTPUT_DIR"/*.so 2>/dev/null || echo "No .so files found"