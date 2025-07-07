#!/bin/bash
set -e

# Docker entrypoint script for Hockeypuck with gRPC plugins

# Wait for database to be ready
wait_for_db() {
    echo "Waiting for database to be ready..."
    while ! pg_isready -h db -U hockeypuck; do
        echo "Database not ready, waiting..."
        sleep 2
    done
    echo "Database is ready!"
}

# Wait for Redis to be ready
wait_for_redis() {
    echo "Waiting for Redis to be ready..."
    while ! redis-cli -h redis ping > /dev/null 2>&1; do
        echo "Redis not ready, waiting..."
        sleep 2
    done
    echo "Redis is ready!"
}

# Wait for gRPC plugins to be ready
wait_for_plugins() {
    echo "Waiting for gRPC plugins to be ready..."
    
    local plugins=(
        "plugin-antiabuse:50001"
        "plugin-mlabuse:50002"
        "plugin-geo:50003"
        "plugin-ml-ratelimit:50004"
        "plugin-threat-intel:50005"
        "plugin-tarpit:50006"
        "plugin-zerotrust:50007"
    )
    
    for plugin in "${plugins[@]}"; do
        echo "Checking $plugin..."
        while ! grpc_health_probe -addr="$plugin" > /dev/null 2>&1; do
            echo "$plugin not ready, waiting..."
            sleep 2
        done
        echo "$plugin is ready!"
    done
    
    echo "All plugins are ready!"
}

# Install grpc_health_probe if not present
if ! command -v grpc_health_probe &> /dev/null; then
    echo "Installing grpc_health_probe..."
    wget -qO/tmp/grpc_health_probe https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/v0.4.24/grpc_health_probe-linux-amd64
    chmod +x /tmp/grpc_health_probe
    export PATH="/tmp:$PATH"
fi

# Wait for dependencies
wait_for_db
wait_for_redis
wait_for_plugins

# Create necessary directories
mkdir -p /var/lib/hockeypuck/{www,recon,plugins}
mkdir -p /var/log/hockeypuck

# Start Hockeypuck
echo "Starting Hockeypuck with gRPC plugins..."
exec /usr/local/bin/hockeypuck-grpc -config "$HOCKEYPUCK_CONFIG"