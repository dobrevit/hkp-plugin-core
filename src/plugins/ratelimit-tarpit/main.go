// Plugin wrapper for dynamic loading
package main

import "hkp-plugin-core/src/plugins/ratelimit-tarpit/ratelimittarpit"
import "hkp-plugin-core/pkg/plugin"

// GetPlugin returns a new instance of the plugin for dynamic loading
func GetPlugin() plugin.Plugin {
	return ratelimittarpit.GetPlugin()
}

// Required for plugin builds
func main() {}