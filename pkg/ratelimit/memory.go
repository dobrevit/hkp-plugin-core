// Package ratelimit - Memory backend implementation
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// MemoryBackend implements the Backend interface using in-memory storage
type MemoryBackend struct {
	// Connection tracking
	connections map[string]int
	connMutex   sync.RWMutex

	// Request rate tracking
	requests map[string][]time.Time
	reqMutex sync.RWMutex

	// Error rate tracking
	errors   map[string][]time.Time
	errMutex sync.RWMutex

	// Ban management
	bans     map[string]BanRecord
	banMutex sync.RWMutex

	// Tor exit nodes
	torExits   map[string]bool
	torMutex   sync.RWMutex
	torUpdated time.Time

	// Global Tor request tracking
	globalTorRequests []time.Time
	globalTorMutex    sync.RWMutex

	// General mutex for stats
	statsMutex sync.RWMutex
}

// BanRecord represents a banned IP record
type BanRecord struct {
	ExpiresAt time.Time
	Reason    string
	BanType   string
}

// NewMemoryBackend creates a new memory backend
func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{
		connections:       make(map[string]int),
		requests:          make(map[string][]time.Time),
		errors:            make(map[string][]time.Time),
		bans:              make(map[string]BanRecord),
		torExits:          make(map[string]bool),
		globalTorRequests: make([]time.Time, 0),
		torUpdated:        time.Now(),
	}
}

// Connection tracking methods

func (m *MemoryBackend) GetConnectionCount(ip string) (int, error) {
	m.connMutex.RLock()
	defer m.connMutex.RUnlock()
	return m.connections[ip], nil
}

func (m *MemoryBackend) IncrementConnectionCount(ip string, ttl time.Duration) error {
	m.connMutex.Lock()
	defer m.connMutex.Unlock()
	m.connections[ip]++
	return nil
}

func (m *MemoryBackend) DecrementConnectionCount(ip string) error {
	m.connMutex.Lock()
	defer m.connMutex.Unlock()
	if count := m.connections[ip]; count > 0 {
		m.connections[ip]--
		if m.connections[ip] == 0 {
			delete(m.connections, ip)
		}
	}
	return nil
}

// Request rate tracking methods

func (m *MemoryBackend) GetRequestCount(ip string, window time.Duration) (int, error) {
	m.reqMutex.Lock()
	defer m.reqMutex.Unlock()

	requests := m.requests[ip]
	if requests == nil {
		return 0, nil
	}

	// Clean up old requests and count recent ones
	cutoff := time.Now().Add(-window)
	recent := make([]time.Time, 0, len(requests))
	count := 0

	for _, reqTime := range requests {
		if reqTime.After(cutoff) {
			recent = append(recent, reqTime)
			count++
		}
	}

	// Update the slice with only recent requests
	if count > 0 {
		m.requests[ip] = recent
	} else {
		delete(m.requests, ip)
	}

	return count, nil
}

func (m *MemoryBackend) IncrementRequestCount(ip string, window time.Duration) error {
	m.reqMutex.Lock()
	defer m.reqMutex.Unlock()

	now := time.Now()
	if m.requests[ip] == nil {
		m.requests[ip] = make([]time.Time, 0)
	}

	m.requests[ip] = append(m.requests[ip], now)

	// Clean up old requests
	cutoff := now.Add(-window)
	recent := make([]time.Time, 0, len(m.requests[ip]))
	for _, reqTime := range m.requests[ip] {
		if reqTime.After(cutoff) {
			recent = append(recent, reqTime)
		}
	}
	m.requests[ip] = recent

	return nil
}

// Error rate tracking methods

func (m *MemoryBackend) GetErrorCount(ip string, window time.Duration) (int, error) {
	m.errMutex.Lock()
	defer m.errMutex.Unlock()

	errors := m.errors[ip]
	if errors == nil {
		return 0, nil
	}

	// Clean up old errors and count recent ones
	cutoff := time.Now().Add(-window)
	recent := make([]time.Time, 0, len(errors))
	count := 0

	for _, errTime := range errors {
		if errTime.After(cutoff) {
			recent = append(recent, errTime)
			count++
		}
	}

	// Update the slice with only recent errors
	if count > 0 {
		m.errors[ip] = recent
	} else {
		delete(m.errors, ip)
	}

	return count, nil
}

func (m *MemoryBackend) IncrementErrorCount(ip string, window time.Duration) error {
	m.errMutex.Lock()
	defer m.errMutex.Unlock()

	now := time.Now()
	if m.errors[ip] == nil {
		m.errors[ip] = make([]time.Time, 0)
	}

	m.errors[ip] = append(m.errors[ip], now)

	// Clean up old errors
	cutoff := now.Add(-window)
	recent := make([]time.Time, 0, len(m.errors[ip]))
	for _, errTime := range m.errors[ip] {
		if errTime.After(cutoff) {
			recent = append(recent, errTime)
		}
	}
	m.errors[ip] = recent

	return nil
}

// Ban management methods

func (m *MemoryBackend) IsBanned(ip string) (bool, time.Time, string, error) {
	m.banMutex.RLock()
	defer m.banMutex.RUnlock()

	ban, exists := m.bans[ip]
	if !exists {
		return false, time.Time{}, "", nil
	}

	// Check if ban has expired
	if time.Now().After(ban.ExpiresAt) {
		// Clean up expired ban asynchronously
		go func() {
			m.banMutex.Lock()
			delete(m.bans, ip)
			m.banMutex.Unlock()
		}()
		return false, time.Time{}, "", nil
	}

	return true, ban.ExpiresAt, ban.Reason, nil
}

func (m *MemoryBackend) BanIP(ip string, duration time.Duration, reason string) error {
	m.banMutex.Lock()
	defer m.banMutex.Unlock()

	expiresAt := time.Now().Add(duration)
	m.bans[ip] = BanRecord{
		ExpiresAt: expiresAt,
		Reason:    reason,
		BanType:   "general",
	}

	return nil
}

func (m *MemoryBackend) UnbanIP(ip string) error {
	m.banMutex.Lock()
	defer m.banMutex.Unlock()
	delete(m.bans, ip)
	return nil
}

// Tor exit node management methods

func (m *MemoryBackend) IsTorExit(ip string) (bool, error) {
	m.torMutex.RLock()
	defer m.torMutex.RUnlock()
	return m.torExits[ip], nil
}

func (m *MemoryBackend) SetTorExits(ips []string, ttl time.Duration) error {
	m.torMutex.Lock()
	defer m.torMutex.Unlock()

	// Clear existing Tor exits
	m.torExits = make(map[string]bool)

	// Add new Tor exits
	for _, ip := range ips {
		m.torExits[ip] = true
	}

	m.torUpdated = time.Now()
	return nil
}

func (m *MemoryBackend) GetTorExitCount() (int, error) {
	m.torMutex.RLock()
	defer m.torMutex.RUnlock()
	return len(m.torExits), nil
}

// Global Tor rate limiting methods

func (m *MemoryBackend) GetGlobalTorRequestCount(window time.Duration) (int, error) {
	m.globalTorMutex.Lock()
	defer m.globalTorMutex.Unlock()

	// Clean up old requests and count recent ones
	cutoff := time.Now().Add(-window)
	recent := make([]time.Time, 0, len(m.globalTorRequests))
	count := 0

	for _, reqTime := range m.globalTorRequests {
		if reqTime.After(cutoff) {
			recent = append(recent, reqTime)
			count++
		}
	}

	// Update the slice with only recent requests
	m.globalTorRequests = recent

	return count, nil
}

func (m *MemoryBackend) IncrementGlobalTorRequestCount(window time.Duration) error {
	m.globalTorMutex.Lock()
	defer m.globalTorMutex.Unlock()

	now := time.Now()
	m.globalTorRequests = append(m.globalTorRequests, now)

	// Clean up old requests
	cutoff := now.Add(-window)
	recent := make([]time.Time, 0, len(m.globalTorRequests))
	for _, reqTime := range m.globalTorRequests {
		if reqTime.After(cutoff) {
			recent = append(recent, reqTime)
		}
	}
	m.globalTorRequests = recent

	return nil
}

// Statistics methods

func (m *MemoryBackend) GetStats() (BackendStats, error) {
	m.statsMutex.RLock()
	defer m.statsMutex.RUnlock()

	// Count currently banned IPs
	m.banMutex.RLock()
	totalBanned := 0
	torBanned := 0
	now := time.Now()

	for ip, ban := range m.bans {
		if now.Before(ban.ExpiresAt) {
			totalBanned++
			if m.torExits[ip] {
				torBanned++
			}
		}
	}
	m.banMutex.RUnlock()

	// Count tracked IPs (IPs with any activity)
	trackedIPs := make(map[string]bool)

	m.connMutex.RLock()
	for ip := range m.connections {
		trackedIPs[ip] = true
	}
	m.connMutex.RUnlock()

	m.reqMutex.RLock()
	for ip := range m.requests {
		trackedIPs[ip] = true
	}
	m.reqMutex.RUnlock()

	m.errMutex.RLock()
	for ip := range m.errors {
		trackedIPs[ip] = true
	}
	m.errMutex.RUnlock()

	m.torMutex.RLock()
	torExitCount := len(m.torExits)
	torLastUpdate := m.torUpdated
	m.torMutex.RUnlock()

	return BackendStats{
		TrackedIPs:    len(trackedIPs),
		BannedIPs:     totalBanned,
		TorBanned:     torBanned,
		BackendType:   "memory",
		TorExitCount:  torExitCount,
		TorLastUpdate: torLastUpdate,
	}, nil
}

// Cleanup methods

func (m *MemoryBackend) Cleanup(ctx context.Context) error {
	now := time.Now()

	// Cleanup expired bans
	m.banMutex.Lock()
	for ip, ban := range m.bans {
		if now.After(ban.ExpiresAt) {
			delete(m.bans, ip)
		}
	}
	m.banMutex.Unlock()

	// Cleanup old request data (older than 1 hour)
	cutoff := now.Add(-time.Hour)

	m.reqMutex.Lock()
	for ip, requests := range m.requests {
		recent := make([]time.Time, 0, len(requests))
		for _, reqTime := range requests {
			if reqTime.After(cutoff) {
				recent = append(recent, reqTime)
			}
		}
		if len(recent) > 0 {
			m.requests[ip] = recent
		} else {
			delete(m.requests, ip)
		}
	}
	m.reqMutex.Unlock()

	// Cleanup old error data (older than 1 hour)
	m.errMutex.Lock()
	for ip, errors := range m.errors {
		recent := make([]time.Time, 0, len(errors))
		for _, errTime := range errors {
			if errTime.After(cutoff) {
				recent = append(recent, errTime)
			}
		}
		if len(recent) > 0 {
			m.errors[ip] = recent
		} else {
			delete(m.errors, ip)
		}
	}
	m.errMutex.Unlock()

	// Cleanup old global Tor requests
	m.globalTorMutex.Lock()
	recent := make([]time.Time, 0, len(m.globalTorRequests))
	for _, reqTime := range m.globalTorRequests {
		if reqTime.After(cutoff) {
			recent = append(recent, reqTime)
		}
	}
	m.globalTorRequests = recent
	m.globalTorMutex.Unlock()

	return nil
}

// Close method

func (m *MemoryBackend) Close() error {
	// Clear all data
	m.connMutex.Lock()
	m.connections = make(map[string]int)
	m.connMutex.Unlock()

	m.reqMutex.Lock()
	m.requests = make(map[string][]time.Time)
	m.reqMutex.Unlock()

	m.errMutex.Lock()
	m.errors = make(map[string][]time.Time)
	m.errMutex.Unlock()

	m.banMutex.Lock()
	m.bans = make(map[string]BanRecord)
	m.banMutex.Unlock()

	m.torMutex.Lock()
	m.torExits = make(map[string]bool)
	m.torMutex.Unlock()

	m.globalTorMutex.Lock()
	m.globalTorRequests = make([]time.Time, 0)
	m.globalTorMutex.Unlock()

	return nil
}