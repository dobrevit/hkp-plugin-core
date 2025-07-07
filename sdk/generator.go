// Package sdk provides tools for generating gRPC plugin templates
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

// PluginTemplate contains the data for generating a plugin
type PluginTemplate struct {
	PluginName     string
	PluginVersion  string
	Description    string
	StructName     string
	ConfigName     string
	HeaderPrefix   string
	ExecutableName string
	Capabilities   []string
	Priority       int
	DefaultPort    int
}

// GeneratePlugin creates a new plugin from the template
func GeneratePlugin(config PluginTemplate, outputDir string) error {
	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate main.go
	mainTemplate, err := template.ParseFiles("template/main.go.template")
	if err != nil {
		return fmt.Errorf("failed to parse main.go template: %w", err)
	}

	mainFile, err := os.Create(filepath.Join(outputDir, "main.go"))
	if err != nil {
		return fmt.Errorf("failed to create main.go: %w", err)
	}
	defer mainFile.Close()

	if err := mainTemplate.Execute(mainFile, config); err != nil {
		return fmt.Errorf("failed to execute main.go template: %w", err)
	}

	// Generate plugin.toml
	tomlTemplate, err := template.ParseFiles("template/plugin.toml.template")
	if err != nil {
		return fmt.Errorf("failed to parse plugin.toml template: %w", err)
	}

	tomlFile, err := os.Create(filepath.Join(outputDir, "plugin.toml"))
	if err != nil {
		return fmt.Errorf("failed to create plugin.toml: %w", err)
	}
	defer tomlFile.Close()

	if err := tomlTemplate.Execute(tomlFile, config); err != nil {
		return fmt.Errorf("failed to execute plugin.toml template: %w", err)
	}

	// Generate Makefile
	makefileContent := fmt.Sprintf(`# Makefile for %s plugin

PLUGIN_NAME = %s
EXECUTABLE = %s

.PHONY: build clean run test

build:
	go build -o $(EXECUTABLE) .

clean:
	rm -f $(EXECUTABLE)

run: build
	PLUGIN_GRPC_ADDRESS=localhost:%d ./$(EXECUTABLE)

test:
	go test -v ./...

install: build
	mkdir -p ../bin
	cp $(EXECUTABLE) ../bin/
	cp plugin.toml ../bin/

.DEFAULT_GOAL := build
`, config.PluginName, config.PluginName, config.ExecutableName, config.DefaultPort)

	makefilePath := filepath.Join(outputDir, "Makefile")
	if err := os.WriteFile(makefilePath, []byte(makefileContent), 0644); err != nil {
		return fmt.Errorf("failed to create Makefile: %w", err)
	}

	// Generate README.md
	readmeContent := fmt.Sprintf(`# %s Plugin

%s

## Building

` + "```bash" + `
make build
` + "```" + `

## Running

` + "```bash" + `
make run
` + "```" + `

## Configuration

Edit ` + "`plugin.toml`" + ` to configure the plugin:

` + "```toml" + `
[config]
enabled = true
# Add your configuration options here
` + "```" + `

## Development

This plugin was generated using the HKP Plugin SDK. To modify:

1. Edit the configuration struct in ` + "`main.go`" + `
2. Implement your business logic in the HTTP request handler
3. Add any background tasks or additional components
4. Update the plugin.toml with new configuration options

## gRPC Interface

This plugin implements the HKPPlugin gRPC interface with the following methods:

- ` + "`Initialize`" + ` - Plugin initialization
- ` + "`HandleHTTPRequest`" + ` - Process HTTP requests
- ` + "`CheckRateLimit`" + ` - Rate limiting checks
- ` + "`GetInfo`" + ` - Plugin information
- ` + "`HealthCheck`" + ` - Health monitoring
- ` + "`Shutdown`" + ` - Graceful shutdown

## Capabilities

%s
`, config.PluginName, config.Description, strings.Join(config.Capabilities, ", "))

	readmePath := filepath.Join(outputDir, "README.md")
	if err := os.WriteFile(readmePath, []byte(readmeContent), 0644); err != nil {
		return fmt.Errorf("failed to create README.md: %w", err)
	}

	return nil
}

// ToStructName converts a plugin name to a Go struct name
func ToStructName(pluginName string) string {
	// Convert kebab-case to PascalCase
	parts := strings.Split(pluginName, "-")
	var result strings.Builder
	
	for _, part := range parts {
		if len(part) > 0 {
			result.WriteString(strings.Title(part))
		}
	}
	result.WriteString("Plugin")
	
	return result.String()
}

// ToConfigName converts a plugin name to a config struct name
func ToConfigName(pluginName string) string {
	return strings.Replace(ToStructName(pluginName), "Plugin", "Config", 1)
}

// ToHeaderPrefix converts a plugin name to a header prefix
func ToHeaderPrefix(pluginName string) string {
	// Convert to title case and remove hyphens
	parts := strings.Split(pluginName, "-")
	var result strings.Builder
	
	for i, part := range parts {
		if i > 0 {
			result.WriteString("-")
		}
		result.WriteString(strings.Title(part))
	}
	
	return result.String()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run generator.go <plugin-name> [output-dir]")
		fmt.Println("Example: go run generator.go my-awesome-plugin ./plugins/my-awesome-plugin-grpc")
		os.Exit(1)
	}

	pluginName := os.Args[1]
	outputDir := fmt.Sprintf("./plugins/%s-grpc", pluginName)
	
	if len(os.Args) > 2 {
		outputDir = os.Args[2]
	}

	config := PluginTemplate{
		PluginName:     pluginName,
		PluginVersion:  "1.0.0",
		Description:    fmt.Sprintf("Generated gRPC plugin: %s", pluginName),
		StructName:     ToStructName(pluginName),
		ConfigName:     ToConfigName(pluginName),
		HeaderPrefix:   ToHeaderPrefix(pluginName),
		ExecutableName: fmt.Sprintf("%s-grpc", pluginName),
		Capabilities:   []string{"custom_processing"},
		Priority:       50,
		DefaultPort:    50100, // Use a high port number for custom plugins
	}

	if err := GeneratePlugin(config, outputDir); err != nil {
		fmt.Printf("Error generating plugin: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Plugin '%s' generated successfully in %s\n", pluginName, outputDir)
	fmt.Printf("To build: cd %s && make build\n", outputDir)
	fmt.Printf("To run: cd %s && make run\n", outputDir)
}