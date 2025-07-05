package main

import (
	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
	"github.com/dobrevit/hkp-plugin-core/src/plugins/zerotrust/zerotrust"
)

// GetPlugin returns the plugin instance for dynamic loading
func GetPlugin() plugin.Plugin {
	return zerotrust.GetPlugin()
}

func main() {}
