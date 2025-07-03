package main

import (
	"hkp-plugin-core/pkg/plugin"
	"hkp-plugin-core/src/plugins/mlabuse/mlabuse"
)

// GetPlugin returns the plugin instance for dynamic loading
func GetPlugin() plugin.Plugin {
	return mlabuse.GetPlugin()
}
