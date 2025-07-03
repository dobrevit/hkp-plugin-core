// Plugin wrapper for dynamic loading
package main

import (
	"hkp-plugin-core/pkg/plugin"
	"hkp-plugin-core/src/plugins/ratelimit-ml/ratelimitml"
)

// GetPlugin returns a new instance of the plugin for dynamic loading
func GetPlugin() plugin.Plugin {
	return ratelimitml.GetPlugin()
}

// Required for plugin builds
func main() {}
