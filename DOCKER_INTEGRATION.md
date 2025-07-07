# Hockeypuck Plugin System Docker Integration

This setup provides a complete integration of Hockeypuck with the plugin system, ensuring both are built in the same environment to avoid version compatibility issues.

## Quick Start

```bash
# Build and start all services
make -f Makefile.docker build
make -f Makefile.docker up

# Check status
make -f Makefile.docker status

# View logs
make -f Makefile.docker logs

# Run integration tests
./scripts/docker-integration-test.sh
```

## Architecture

The Docker setup consists of:

1. **Multi-stage Dockerfile** (`Dockerfile.hockeypuck-integration`)
   - Stage 1: Base image with common dependencies
   - Stage 2: Build plugins
   - Stage 3: Build Hockeypuck
   - Stage 4: Final runtime image with both components

2. **Docker Compose Services**
   - `db`: PostgreSQL 16 for Hockeypuck storage
   - `redis`: Redis 7 for plugin caching and rate limiting
   - `hockeypuck`: The main Hockeypuck server with integrated plugins
   - `dev-tools`: (optional) Development container for testing
   - `prometheus`: (optional) Metrics collection
   - `grafana`: (optional) Metrics visualization

## Configuration

The default configuration is created in the Docker image, but you can override it by:

1. Editing `config/hockeypuck.conf`
2. The configuration is mounted as a volume in docker-compose.yml

### Key Configuration Sections

```toml
[hockeypuck]
datadir = "/var/lib/hockeypuck"

[hockeypuck.plugins]
enabled = true
directory = "/var/lib/hockeypuck/plugins"
```

## Plugin Management

Plugins are automatically copied to `/var/lib/hockeypuck/plugins/` during the Docker build. The integration ensures:

- Both Hockeypuck and plugins are built with `golang:1.24-bookworm`
- All dependencies are synchronized
- No version mismatch issues

## Testing

### Basic Health Check
```bash
# Check if Hockeypuck is running
curl http://localhost:11371/pks/lookup?op=stats
```

### Submit a Test Key
```bash
curl -X POST -H "Content-Type: application/pgp-keys" \
  --data-binary @test-key.asc \
  http://localhost:11371/pks/add
```

### Check Plugin Status
```bash
# If plugin management endpoints are configured
curl http://localhost:11371/plugins/status
```

## Development

### Access Development Shell
```bash
# With dev profile enabled
make -f Makefile.docker dev
make -f Makefile.docker dev-shell
```

### Rebuild After Changes
```bash
make -f Makefile.docker rebuild
```

## Monitoring

Enable Prometheus and Grafana:
```bash
make -f Makefile.docker monitor
```

Access:
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/admin)

## Troubleshooting

### View Logs
```bash
# All services
docker-compose logs -f

# Just Hockeypuck
docker-compose logs -f hockeypuck
```

### Check Plugin Loading
```bash
docker-compose exec hockeypuck ls -la /var/lib/hockeypuck/plugins/
```

### Database Connection Issues
```bash
# Check PostgreSQL
docker-compose exec db psql -U hockeypuck -c "SELECT 1"
```

### Clean Everything
```bash
make -f Makefile.docker clean
```

## Production Considerations

1. **Security**
   - Change default PostgreSQL password
   - Use proper TLS certificates for HTTPS
   - Configure firewall rules

2. **Performance**
   - Adjust PostgreSQL configuration for your workload
   - Configure Redis memory limits
   - Set appropriate resource limits in docker-compose.yml

3. **Persistence**
   - Backup volumes regularly
   - Use named volumes for data persistence
   - Consider replication for high availability

## Plugin Development

When developing new plugins:

1. Build in the same environment:
   ```bash
   docker run --rm -v "$PWD:/workspace" -w /workspace \
     golang:1.24-bookworm \
     make plugins
   ```

2. Copy to plugin directory and rebuild the Docker image

3. Test with the integration test script