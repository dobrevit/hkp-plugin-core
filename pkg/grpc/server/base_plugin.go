package server

import (
	"context"
	"fmt"

	"github.com/dobrevit/hkp-plugin-core/pkg/grpc/proto"
)

// BasePlugin provides a basic implementation of PluginImplementation
// that plugins can embed and override specific methods
type BasePlugin struct {
	Name         string
	Version      string
	Description  string
	Capabilities []string
	Config       map[string]interface{}
}

// Initialize implements PluginImplementation
func (p *BasePlugin) Initialize(config map[string]interface{}) error {
	p.Config = config
	return nil
}

// GetInfo implements PluginImplementation
func (p *BasePlugin) GetInfo() PluginInfo {
	return PluginInfo{
		Name:         p.Name,
		Version:      p.Version,
		Description:  p.Description,
		Capabilities: p.Capabilities,
		Metadata:     make(map[string]string),
	}
}

// HandleHTTPRequest implements PluginImplementation with a default pass-through
func (p *BasePlugin) HandleHTTPRequest(ctx context.Context, req *proto.HTTPRequest) (*proto.HTTPResponse, error) {
	// Default implementation - pass through
	return &proto.HTTPResponse{
		StatusCode:    200,
		Headers:       make(map[string]string),
		Body:          req.Body,
		ContinueChain: true,
	}, nil
}

// HandleKeyChange implements PluginImplementation with a no-op
func (p *BasePlugin) HandleKeyChange(ctx context.Context, event *proto.KeyChangeEvent) error {
	// Default implementation - do nothing
	return nil
}

// Shutdown implements PluginImplementation
func (p *BasePlugin) Shutdown() error {
	// Default implementation - nothing to clean up
	return nil
}

// SimplePlugin is a helper for creating simple plugins
type SimplePlugin struct {
	BasePlugin
	
	// Handlers that can be set by the plugin
	HTTPHandler      func(context.Context, *proto.HTTPRequest) (*proto.HTTPResponse, error)
	KeyChangeHandler func(context.Context, *proto.KeyChangeEvent) error
	InitHandler      func(map[string]interface{}) error
	ShutdownHandler  func() error
}

// Initialize calls the custom init handler if set
func (p *SimplePlugin) Initialize(config map[string]interface{}) error {
	if err := p.BasePlugin.Initialize(config); err != nil {
		return err
	}
	
	if p.InitHandler != nil {
		return p.InitHandler(config)
	}
	
	return nil
}

// HandleHTTPRequest calls the custom handler if set
func (p *SimplePlugin) HandleHTTPRequest(ctx context.Context, req *proto.HTTPRequest) (*proto.HTTPResponse, error) {
	if p.HTTPHandler != nil {
		return p.HTTPHandler(ctx, req)
	}
	
	return p.BasePlugin.HandleHTTPRequest(ctx, req)
}

// HandleKeyChange calls the custom handler if set
func (p *SimplePlugin) HandleKeyChange(ctx context.Context, event *proto.KeyChangeEvent) error {
	if p.KeyChangeHandler != nil {
		return p.KeyChangeHandler(ctx, event)
	}
	
	return p.BasePlugin.HandleKeyChange(ctx, event)
}

// Shutdown calls the custom handler if set
func (p *SimplePlugin) Shutdown() error {
	if p.ShutdownHandler != nil {
		return p.ShutdownHandler()
	}
	
	return p.BasePlugin.Shutdown()
}

// ConfigHelper provides utility methods for working with plugin configuration
type ConfigHelper struct {
	Config map[string]interface{}
}

// NewConfigHelper creates a new config helper
func NewConfigHelper(config map[string]interface{}) *ConfigHelper {
	if config == nil {
		config = make(map[string]interface{})
	}
	return &ConfigHelper{Config: config}
}

// GetString retrieves a string configuration value
func (c *ConfigHelper) GetString(key string, defaultValue string) string {
	if val, ok := c.Config[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultValue
}

// GetInt retrieves an integer configuration value
func (c *ConfigHelper) GetInt(key string, defaultValue int) int {
	if val, ok := c.Config[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		}
	}
	return defaultValue
}

// GetBool retrieves a boolean configuration value
func (c *ConfigHelper) GetBool(key string, defaultValue bool) bool {
	if val, ok := c.Config[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return defaultValue
}

// GetFloat retrieves a float configuration value
func (c *ConfigHelper) GetFloat(key string, defaultValue float64) float64 {
	if val, ok := c.Config[key]; ok {
		switch v := val.(type) {
		case float64:
			return v
		case float32:
			return float64(v)
		case int:
			return float64(v)
		case int64:
			return float64(v)
		}
	}
	return defaultValue
}

// GetStringSlice retrieves a string slice configuration value
func (c *ConfigHelper) GetStringSlice(key string) []string {
	if val, ok := c.Config[key]; ok {
		switch v := val.(type) {
		case []string:
			return v
		case []interface{}:
			result := make([]string, 0, len(v))
			for _, item := range v {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			return result
		}
	}
	return nil
}

// GetSubConfig retrieves a nested configuration map
func (c *ConfigHelper) GetSubConfig(key string) map[string]interface{} {
	if val, ok := c.Config[key]; ok {
		if m, ok := val.(map[string]interface{}); ok {
			return m
		}
	}
	return nil
}

// MustGetString retrieves a string configuration value or panics
func (c *ConfigHelper) MustGetString(key string) string {
	if val, ok := c.Config[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	panic(fmt.Sprintf("required configuration key '%s' not found or not a string", key))
}