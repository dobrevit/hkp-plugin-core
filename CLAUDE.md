# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Architecture

This is the HKP Plugin System - a comprehensive, modular security and operational framework for Hockeypuck OpenPGP key servers. The system implements a sophisticated plugin architecture with Hockeypuck-compatible interfaces, event-driven communication, hot-reload capabilities, and advanced security features.

### Core Components

- **Plugin Framework**: Uses Go's plugin architecture (`.so` files) for hot-pluggable modules
- **Event System**: Hybrid system bridging Hockeypuck's KeyChange notifications with flexible plugin events
- **Middleware Chain**: HTTP middleware integration compatible with `github.com/carbocation/interpose`
- **Storage Interface**: Compatible with Hockeypuck's storage patterns without copying AGPL code
- **Configuration**: Matches Hockeypuck's TOML structure and template system
- **Resource Management**: Proper lifecycle management using `gopkg.in/tomb.v2`

### Plugin Categories

1. **Security Plugins**: Zero Trust, ML Abuse Detection
2. **Rate Limiting Plugins**: Geographic Analysis, Threat Intelligence, ML Extension, Tarpit
3. **Operational Plugins**: Anti-Abuse, Basic Rate Limiting

### Key Architecture Files

- `main.go`: Example server implementation with plugin integration
- `pkg/plugin/`: Core plugin interfaces and management (Hockeypuck-compatible)
- `pkg/hkpstorage/`: Hockeypuck-compatible storage interfaces
- `pkg/events/`: Event system bridging Hockeypuck and plugin patterns
- `pkg/config/`: Hockeypuck-compatible configuration structures
- `pkg/middleware/`: Interpose-compatible middleware chain management
- `pkg/ratelimit/`: Rate limiting backend implementations
- `src/plugins/`: Individual plugin implementations
- `cmd/interpose/`: Main application entry point

## Development Commands

### Building
```bash
# Build all plugins and application
make all

# Build only plugins
make plugins

# Build specific plugin
make plugin-antiabuse

# Build main application
make app
```

### Testing
```bash
# Run all tests (unit + integration)
make test

# Run with coverage
make test-coverage

# Run verbose tests
make test-verbose

# Run only unit tests
make test-unit

# Direct test script usage
./scripts/test-all.sh
./scripts/test-all.sh --coverage
./scripts/test-all.sh --verbose
```

### Code Quality
```bash
# Format code
make fmt

# Run linter (requires golangci-lint)
make lint
```

### Development Workflow
```bash
# Development mode (build and run)
make dev

# Run application with config
make run
```

## Plugin Development

### Plugin Interface
All plugins must implement the `plugin.Plugin` interface (Hockeypuck-compatible):
- `Initialize(ctx, host, config) error`
- `Name() string`
- `Version() string`
- `Description() string`
- `Dependencies() []PluginDependency`
- `Shutdown(ctx) error`

### Plugin Host Interface (Hockeypuck-compatible)
- `Storage() hkpstorage.Storage` - Access Hockeypuck storage
- `Config() *config.Settings` - Access Hockeypuck-style configuration
- `Logger() *logrus.Logger` - Use logrus (same as Hockeypuck)
- `PublishEvent(events.PluginEvent) error` - Generic event publishing
- `SubscribeKeyChanges(func(KeyChange) error) error` - Hockeypuck-style notifications
- `PublishThreatDetected(events.ThreatInfo) error` - Security event convenience method

### Plugin Loading Order
Critical: Plugins must be loaded in dependency order:
1. Threat Intelligence (priority 15)
2. Geographic Analysis (priority 20)
3. ML Rate Limiting (priority 25)
4. ML Abuse Detection (priority 30)
5. Zero Trust (priority 40)
6. Tarpit (priority 50)

### Event System
Plugins communicate via events:
```go
// Subscribe to events
host.SubscribeEvent("threat.detected", handler)

// Publish events
host.PublishEvent(plugin.PluginEvent{
    Type: "abuse.detected",
    Source: pluginName,
    Data: eventData,
})
```

### Plugin Lifecycle Management 🔥

The `/pkg/management/` package provides production-ready plugin lifecycle management:

**Key Features:**
- **Hot Reload**: Graceful plugin reloading with request draining
- **Health Monitoring**: Real-time plugin health checks
- **Configuration Management**: Dynamic config updates
- **HTTP Endpoints**: Ready-to-use management API
- **Request Draining**: Zero-downtime plugin transitions
- **Rollback Support**: Automatic rollback on failures

**HTTP Endpoints for Hockeypuck:**
- `GET /plugins/status` - System status and plugin states
- `GET /plugins/list` - Detailed plugin information
- `GET /plugins/health` - Health checks for all plugins
- `POST /plugins/reload?plugin=<name>` - Hot reload specific plugin
- `GET/PUT /plugins/config?plugin=<name>` - Config management

**Integration Example:**
```go
// In Hockeypuck's server initialization
pluginManager := management.NewPluginManager(host, settings, logger)
pluginSystem, _ := integration.InitializePlugins(ctx, host, settings)
pluginManager.SetPluginSystem(pluginSystem)

// Register HTTP endpoints
mux.HandleFunc("/plugins/status", pluginManager.StatusHandler)
mux.HandleFunc("/plugins/reload", pluginManager.ReloadHandler)
// ... other endpoints
```

This enables zero-downtime plugin updates and comprehensive monitoring for production Hockeypuck deployments!

## Project Structure

```
├── cmd/interpose/          # Main application
├── pkg/                    # Core packages
│   ├── config/             # AGPL-compliant configuration
│   ├── events/             # Event system (Hockeypuck bridge)
│   ├── hkpstorage/         # Clean-room storage interfaces
│   ├── integration/        # Simple Hockeypuck integration
│   ├── management/         # Plugin lifecycle management ⭐
│   ├── metrics/            # Prometheus metrics
│   ├── middleware/         # Interpose-compatible middleware
│   ├── plugin/             # Plugin management core
│   ├── ratelimit/          # Rate limiting backends
│   ├── recovery/           # Circuit breakers and recovery
│   ├── resources/          # Resource monitoring
│   ├── security/           # Security verification
│   ├── storage/            # Storage interfaces
│   └── versioning/         # Version management
├── src/plugins/            # Plugin implementations
│   ├── antiabuse/          # Basic anti-abuse
│   ├── mlabuse/            # ML abuse detection
│   ├── ratelimit-geo/      # Geographic analysis
│   ├── ratelimit-ml/       # ML rate limiting
│   ├── ratelimit-tarpit/   # Tarpit defense
│   ├── ratelimit-threat/   # Threat intelligence
│   └── zerotrust/          # Zero trust security
├── tests/                  # Integration tests
└── scripts/                # Build and test scripts
```

## Configuration

### Build Configuration
- Go version: 1.24
- Build mode: Plugin (for `.so` files)
- Main dependencies: interpose, mux, redis, geoip2, prometheus, tomb

### Plugin Configuration
Each plugin has its own TOML configuration section. The main application loads configuration from `cmd/interpose/config.toml`.

## Testing Strategy

The project uses a comprehensive testing approach:
- Unit tests for individual plugins and packages
- Integration tests that build and test plugin interactions
- Coverage reporting via `go tool cover`
- Test timeout: 10 minutes default

## Security Considerations

This is a security-focused project implementing:
- Zero Trust Network Access (ZTNA)
- ML-based abuse detection
- Threat intelligence integration
- Geographic anomaly detection
- Tarpit and honeypot systems

All plugins handle sensitive security data and must follow secure coding practices.

## Development Notes

- Plugins are compiled as shared libraries (`.so` files)
- The system uses tomb.Tomb for graceful goroutine management
- Event-driven architecture enables loose coupling between plugins
- Hot-reload capabilities allow plugin updates without server restart
- Resource monitoring and circuit breakers ensure system stability
