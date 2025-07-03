// Plugin wrapper for dynamic loading
package main

import "hkp-plugin-core/src/plugins/ratelimit-geo/ratelimitgeo"
import "hkp-plugin-core/pkg/plugin"

// GetPlugin returns a new instance of the plugin for dynamic loading
func GetPlugin() plugin.Plugin {
	return ratelimitgeo.GetPlugin()
}

// Required for plugin builds
func main() {}