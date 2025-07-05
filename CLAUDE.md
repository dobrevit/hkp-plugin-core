# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Architecture

This is the HKP Plugin System - a comprehensive, modular security and operational framework for Hockeypuck OpenPGP key servers. The system implements a sophisticated plugin architecture with event-driven communication, hot-reload capabilities, and advanced security features.

### Core Components

- **Plugin Framework**: Uses Go's plugin architecture (`.so` files) for hot-pluggable modules
- **Event System**: Plugins communicate through publish-subscribe event system
- **Middleware Chain**: HTTP middleware integration using `github.com/carbocation/interpose`
- **Resource Management**: Proper lifecycle management using `gopkg.in/tomb.v2`

### Plugin Categories

1. **Security Plugins**: Zero Trust, ML Abuse Detection
2. **Rate Limiting Plugins**: Geographic Analysis, Threat Intelligence, ML Extension, Tarpit
3. **Operational Plugins**: Anti-Abuse, Basic Rate Limiting

### Key Architecture Files

- `main.go`: Example server implementation with plugin integration
- `pkg/plugin/`: Core plugin interfaces and management
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
All plugins must implement the `plugin.Plugin` interface:
- `Initialize(ctx, host, config) error`
- `Name() string`
- `Version() string`
- `Description() string`
- `Dependencies() []PluginDependency`
- `Shutdown(ctx) error`

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

## Project Structure

```
├── cmd/interpose/          # Main application
├── pkg/                    # Core packages
│   ├── plugin/             # Plugin management
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
