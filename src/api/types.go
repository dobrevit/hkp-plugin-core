package pluginapi

import (
	"net/http"
	"time"
)

// PluginRoute defines a route that a plugin wants to register
type PluginRoute struct {
	Pattern string
	Handler http.HandlerFunc
	Methods []string // If empty, accepts all methods
}

// PluginDependency represents a plugin dependency
type PluginDependency struct {
	Name       string
	MinVersion string
}

// PluginEvent represents an event in the plugin system
type PluginEvent struct {
	Type      string
	Source    string
	Timestamp time.Time
	Data      interface{}
}
