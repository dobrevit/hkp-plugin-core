// Plugin wrapper for dynamic loading
package main

import (
	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
	"github.com/dobrevit/hkp-plugin-core/src/plugins/ratelimit-tarpit/ratelimittarpit"
)

// GetPlugin returns a new instance of the plugin for dynamic loading
func GetPlugin() plugin.Plugin {
	return ratelimittarpit.GetPlugin()
}

// Required for plugin builds
func main() {}
