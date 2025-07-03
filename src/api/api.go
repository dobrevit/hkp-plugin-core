// Package pluginapi provides the plugin interface for Hockeypuck with Interpose support
package pluginapi

import (
	"context"
	"time"
)

// pluginHost implements PluginHost interface
type pluginHost struct {
	manager *PluginManager
	logger  Logger
}

func (ph *pluginHost) Storage() interface{} {
	// Return storage interface
	return nil
}

func (ph *pluginHost) Config() interface{} {
	// Return config interface
	return nil
}

func (ph *pluginHost) Metrics() interface{} {
	// Return metrics interface
	return nil
}

func (ph *pluginHost) RegisterTask(name string, interval time.Duration, task func(context.Context) error) error {
	// Start background task
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		ctx := context.Background()
		for {
			select {
			case <-ticker.C:
				if err := task(ctx); err != nil {
					ph.logger.Error("Task error", "task", name, "error", err)
				}
			case <-ph.manager.shutdownCh:
				return
			}
		}
	}()

	return nil
}

func (ph *pluginHost) PublishEvent(event PluginEvent) error {
	return ph.manager.eventBus.Publish(event)
}

func (ph *pluginHost) SubscribeEvent(eventType string, handler func(PluginEvent) error) error {
	return ph.manager.eventBus.Subscribe(eventType, handler)
}

func (ph *pluginHost) Logger() Logger {
	return ph.logger
}
