# Docker gRPC Plugin Setup Guide

This document explains how to use the Docker Compose setup for testing Hockeypuck with gRPC plugins.

## Architecture Overview

The gRPC plugin architecture consists of:

- **Hockeypuck Server**: Main HKP server (`src/hockeypuck`) with gRPC plugin client integration
- **Individual Plugin Services**: Each plugin runs as a separate gRPC server
- **Plugin Manager**: Discovery and health monitoring service
- **Supporting Services**: PostgreSQL, Redis, Prometheus, Grafana

The setup uses the authentic Hockeypuck codebase from `src/hockeypuck` with integrated gRPC plugin support via the `github.com/dobrevit/hkp-plugin-core` package.

## Quick Start

### 1. Build and Start All Services

```bash
# Start the complete gRPC plugin stack
docker-compose -f docker-compose.grpc.yml up --build

# Or start with monitoring
docker-compose -f docker-compose.grpc.yml --profile monitoring up --build
```

### 2. Individual Plugin Development

```bash
# Build and test a specific plugin
docker-compose -f docker-compose.grpc.yml up --build plugin-antiabuse

# View plugin logs
docker-compose -f docker-compose.grpc.yml logs -f plugin-antiabuse

# Test plugin health
docker-compose -f docker-compose.grpc.yml exec plugin-antiabuse grpc_health_probe -addr=localhost:50001
```

### 3. Development Mode

```bash
# Start with development tools
docker-compose -f docker-compose.grpc.yml --profile dev up --build

# Access development container
docker-compose -f docker-compose.grpc.yml exec dev-tools bash
```

## Service Endpoints

### Hockeypuck
- **HKP Port**: http://localhost:21371
- **Recon Port**: http://localhost:21370 (if enabled)
- **Management API**: http://localhost:21372

### Plugin Manager
- **Management API**: http://localhost:21373
- **Plugin Status**: http://localhost:21373/plugins/status
- **Plugin Health**: http://localhost:21373/plugins/health

### Monitoring (with --profile monitoring)
- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (admin/admin)

## Plugin gRPC Ports

| Plugin | Port | Service Name |
|--------|------|--------------|
| antiabuse | 50001 | plugin-antiabuse |
| mlabuse | 50002 | plugin-mlabuse |
| geo | 50003 | plugin-geo |
| ml-ratelimit | 50004 | plugin-ml-ratelimit |
| threat-intel | 50005 | plugin-threat-intel |
| tarpit | 50006 | plugin-tarpit |
| zerotrust | 50007 | plugin-zerotrust |

## Configuration

### Environment Variables

Plugin-specific environment variables can be set in docker-compose.grpc.yml:

```yaml
plugin-antiabuse:
  environment:
    PLUGIN_GRPC_ADDRESS: "0.0.0.0:50001"
    REDIS_URL: "redis://redis:6379"
    CUSTOM_CONFIG: "value"
```

### Plugin Configuration

Each plugin uses `/etc/plugins/plugin.toml` for configuration:

```toml
[plugin]
name = "antiabuse"
version = "1.0.0"
description = "Anti-abuse plugin"

[config]
enabled = true
threshold = 0.8

[grpc]
address = "0.0.0.0:50001"
```

## Health Monitoring

### Plugin Health Checks

All plugins include health checks using `grpc_health_probe`:

```bash
# Check individual plugin health
grpc_health_probe -addr=plugin-antiabuse:50001
grpc_health_probe -addr=plugin-mlabuse:50002
```

### Health Check Endpoints

- **Plugin Manager**: `GET /plugins/health`
- **Individual Plugin Status**: `GET /plugins/status`

## Troubleshooting

### Common Issues

1. **Plugin Not Starting**:
   ```bash
   # Check plugin logs
   docker-compose -f docker-compose.grpc.yml logs plugin-antiabuse
   
   # Check if binary exists in container
   docker-compose -f docker-compose.grpc.yml exec plugin-antiabuse ls -la /usr/local/bin/
   
   # Check if port is available
   docker-compose -f docker-compose.grpc.yml exec plugin-antiabuse netstat -tlnp
   ```

2. **gRPC Connection Errors**:
   ```bash
   # Test gRPC connectivity
   docker-compose -f docker-compose.grpc.yml exec hockeypuck grpc_health_probe -addr=plugin-antiabuse:50001
   ```

3. **Plugin Health Check Failing**:
   ```bash
   # Check plugin health manually
   docker-compose -f docker-compose.grpc.yml exec plugin-antiabuse grpc_health_probe -addr=localhost:50001
   ```

### Debug Commands

```bash
# View all service status
docker-compose -f docker-compose.grpc.yml ps

# Check plugin discovery
docker-compose -f docker-compose.grpc.yml exec plugin-manager curl localhost:8080/plugins/list

# Monitor plugin metrics
docker-compose -f docker-compose.grpc.yml exec prometheus curl localhost:9090/api/v1/targets

# View Hockeypuck logs
docker-compose -f docker-compose.grpc.yml logs -f hockeypuck
```

## Development Workflow

### 1. Plugin Development

```bash
# Generate new plugin
cd sdk
go run generator.go my-new-plugin

# Add to docker-compose.grpc.yml
# Build and test
docker-compose -f docker-compose.grpc.yml up --build plugin-my-new-plugin
```

### 2. Plugin Testing

```bash
# Test HTTP request handling
curl -X POST http://localhost:21371/pks/add \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "keytext=-----BEGIN PGP PUBLIC KEY BLOCK-----..."

# Check plugin metrics
curl http://localhost:21373/plugins/status
```

### 3. Integration Testing

```bash
# Start all services
docker-compose -f docker-compose.grpc.yml up --build

# Run integration tests
docker-compose -f docker-compose.grpc.yml exec dev-tools bash
cd /workspace
go test ./tests/...
```

## Performance Considerations

### Resource Limits

Each plugin service can be configured with resource limits:

```yaml
plugin-antiabuse:
  deploy:
    resources:
      limits:
        memory: 256M
        cpus: '0.5'
      reservations:
        memory: 128M
        cpus: '0.25'
```

### Scaling

Individual plugins can be scaled independently:

```bash
# Scale specific plugin
docker-compose -f docker-compose.grpc.yml up --scale plugin-antiabuse=3
```

## Security Considerations

### Network Isolation

- All services run in the `hockeypuck-net` network
- Only necessary ports are exposed to the host
- Plugin communication is internal-only

### User Security

- Each plugin runs as a non-root user
- Plugin data is stored in dedicated volumes
- Configuration is read-only mounted

## Maintenance

### Updating Plugins

```bash
# Update specific plugin
docker-compose -f docker-compose.grpc.yml up --build plugin-antiabuse

# Hot reload (if supported)
curl -X POST http://localhost:21373/plugins/reload?plugin=antiabuse
```

### Log Management

```bash
# View logs by service
docker-compose -f docker-compose.grpc.yml logs plugin-antiabuse

# Follow logs for all plugins
docker-compose -f docker-compose.grpc.yml logs -f plugin-antiabuse plugin-mlabuse
```

### Data Persistence

Important data is stored in named volumes:
- `hockeypuck-data`: Hockeypuck data directory
- `postgres-data`: PostgreSQL database
- `redis-data`: Redis cache
- `ml-models`: ML model data
- `geoip-data`: GeoIP database
- `threat-data`: Threat intelligence cache

## Migration from Legacy Plugins

See [MIGRATION.md](MIGRATION.md) for detailed migration instructions from the legacy Go plugin system to gRPC plugins.