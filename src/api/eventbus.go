package pluginapi

import "sync"

// EventBus handles event publishing and subscription
type EventBus struct {
	subscribers map[string][]func(PluginEvent) error
	mu          sync.RWMutex
}

func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[string][]func(PluginEvent) error),
	}
}

func (eb *EventBus) Publish(event PluginEvent) error {
	eb.mu.RLock()
	handlers := eb.subscribers[event.Type]
	eb.mu.RUnlock()

	for _, handler := range handlers {
		go func(h func(PluginEvent) error) {
			if err := h(event); err != nil {
				// Log error
			}
		}(handler)
	}

	return nil
}

func (eb *EventBus) Subscribe(eventType string, handler func(PluginEvent) error) error {
	eb.mu.Lock()
	eb.subscribers[eventType] = append(eb.subscribers[eventType], handler)
	eb.mu.Unlock()

	return nil
}
