// Package ratelimit - Tor exit node updater implementation
package ratelimit

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/tomb.v2"
)

// TorExitUpdater manages Tor exit node list updates
type TorExitUpdater struct {
	config  TorConfig
	backend Backend
	tomb    tomb.Tomb
	client  *http.Client
	dataDir string
}

// NewTorExitUpdater creates a new Tor exit updater
func NewTorExitUpdater(config TorConfig, backend Backend) *TorExitUpdater {
	return &TorExitUpdater{
		config:  config,
		backend: backend,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetDataDir sets the data directory for cache files
func (t *TorExitUpdater) SetDataDir(dataDir string) {
	t.dataDir = dataDir
}

// Run starts the Tor exit updater background task
func (t *TorExitUpdater) Run() error {
	// Load initial cache if available
	if err := t.loadCacheFile(); err != nil {
		// Log error but continue - we'll fetch fresh data
	}

	// Initial fetch
	if err := t.updateTorExitList(); err != nil {
		// Log error but continue with timer
	}

	// Set up periodic updates
	ticker := time.NewTicker(t.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := t.updateTorExitList(); err != nil {
				// Log error but continue
			}
		case <-t.tomb.Dying():
			return nil
		}
	}
}

// Stop stops the Tor exit updater
func (t *TorExitUpdater) Stop() {
	t.tomb.Kill(nil)
	t.tomb.Wait()
}

// updateTorExitList fetches and updates the Tor exit node list
func (t *TorExitUpdater) updateTorExitList() error {
	// Create HTTP request
	req, err := http.NewRequest("GET", t.config.ExitNodeListURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set User-Agent if configured
	if t.config.UserAgent != "" {
		req.Header.Set("User-Agent", t.config.UserAgent)
	}

	// Add context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	// Perform request
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch Tor exit list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse the response
	ips, err := t.parseTorExitList(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to parse Tor exit list: %w", err)
	}

	// Update backend with new list
	if err := t.backend.SetTorExits(ips, 24*time.Hour); err != nil {
		return fmt.Errorf("failed to update backend: %w", err)
	}

	// Save to cache file
	if err := t.saveCacheFile(ips); err != nil {
		// Log error but don't fail the update
	}

	return nil
}

// parseTorExitList parses the Tor exit node list from the response
func (t *TorExitUpdater) parseTorExitList(reader io.Reader) ([]string, error) {
	var ips []string
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Validate IP address
		if ip := net.ParseIP(line); ip != nil {
			ips = append(ips, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	return ips, nil
}

// getCacheFilePath returns the full path to the cache file
func (t *TorExitUpdater) getCacheFilePath() string {
	cacheFile := t.config.CacheFilePath

	// If it's a relative path, use dataDir
	if !filepath.IsAbs(cacheFile) && t.dataDir != "" {
		return filepath.Join(t.dataDir, cacheFile)
	}

	return cacheFile
}

// saveCacheFile saves the Tor exit list to a cache file
func (t *TorExitUpdater) saveCacheFile(ips []string) error {
	if t.config.CacheFilePath == "" {
		return nil // No cache file configured
	}

	cacheFile := t.getCacheFilePath()

	// Create directory if it doesn't exist
	if dir := filepath.Dir(cacheFile); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create cache directory: %w", err)
		}
	}

	// Create temporary file first
	tempFile := cacheFile + ".tmp"
	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("failed to create temp cache file: %w", err)
	}

	// Write header with timestamp
	fmt.Fprintf(file, "# Tor exit nodes cache\n")
	fmt.Fprintf(file, "# Updated: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(file, "# Count: %d\n", len(ips))
	fmt.Fprintf(file, "#\n")

	// Write IP addresses
	for _, ip := range ips {
		fmt.Fprintf(file, "%s\n", ip)
	}

	if err := file.Close(); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to close temp cache file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempFile, cacheFile); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to rename cache file: %w", err)
	}

	return nil
}

// loadCacheFile loads the Tor exit list from cache file
func (t *TorExitUpdater) loadCacheFile() error {
	if t.config.CacheFilePath == "" {
		return nil // No cache file configured
	}

	cacheFile := t.getCacheFilePath()

	// Check if file exists
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		return nil // File doesn't exist, not an error
	}

	// Check file age - if older than update interval * 2, consider it stale
	fileInfo, err := os.Stat(cacheFile)
	if err != nil {
		return fmt.Errorf("failed to stat cache file: %w", err)
	}

	if time.Since(fileInfo.ModTime()) > t.config.UpdateInterval*2 {
		// File is stale, but we can still load it as a fallback
	}

	// Open and read file
	file, err := os.Open(cacheFile)
	if err != nil {
		return fmt.Errorf("failed to open cache file: %w", err)
	}
	defer file.Close()

	// Parse the cached list
	ips, err := t.parseTorExitList(file)
	if err != nil {
		return fmt.Errorf("failed to parse cache file: %w", err)
	}

	// Update backend with cached list
	if err := t.backend.SetTorExits(ips, 24*time.Hour); err != nil {
		return fmt.Errorf("failed to update backend from cache: %w", err)
	}

	return nil
}

// GetCacheInfo returns information about the cache file
func (t *TorExitUpdater) GetCacheInfo() (*CacheInfo, error) {
	if t.config.CacheFilePath == "" {
		return nil, fmt.Errorf("no cache file configured")
	}

	cacheFile := t.getCacheFilePath()

	fileInfo, err := os.Stat(cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			return &CacheInfo{
				Exists: false,
				Path:   cacheFile,
			}, nil
		}
		return nil, fmt.Errorf("failed to stat cache file: %w", err)
	}

	// Count entries in cache file
	count, err := t.countCacheEntries(cacheFile)
	if err != nil {
		return nil, fmt.Errorf("failed to count cache entries: %w", err)
	}

	return &CacheInfo{
		Exists:  true,
		Path:    cacheFile,
		Size:    fileInfo.Size(),
		ModTime: fileInfo.ModTime(),
		Count:   count,
		IsStale: time.Since(fileInfo.ModTime()) > t.config.UpdateInterval*2,
	}, nil
}

// countCacheEntries counts the number of IP entries in the cache file
func (t *TorExitUpdater) countCacheEntries(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			if net.ParseIP(line) != nil {
				count++
			}
		}
	}

	return count, scanner.Err()
}

// ClearCache removes the cache file
func (t *TorExitUpdater) ClearCache() error {
	if t.config.CacheFilePath == "" {
		return nil // No cache file configured
	}

	cacheFile := t.getCacheFilePath()

	if err := os.Remove(cacheFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove cache file: %w", err)
	}

	return nil
}

// ForceUpdate forces an immediate update of the Tor exit list
func (t *TorExitUpdater) ForceUpdate() error {
	return t.updateTorExitList()
}

// CacheInfo provides information about the cache file
type CacheInfo struct {
	Exists  bool      `json:"exists"`
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	Count   int       `json:"count"`
	IsStale bool      `json:"is_stale"`
}

// ValidateConfig validates the Tor configuration
func ValidateConfig(config TorConfig) error {
	if !config.Enabled {
		return nil // No validation needed if disabled
	}

	// Validate URL
	if config.ExitNodeListURL == "" {
		return fmt.Errorf("exitNodeListURL is required when Tor protection is enabled")
	}

	// Validate update interval
	if config.UpdateInterval <= 0 {
		return fmt.Errorf("updateInterval must be positive")
	}

	if config.UpdateInterval < 5*time.Minute {
		return fmt.Errorf("updateInterval should be at least 5 minutes to avoid overloading the Tor list provider")
	}

	// Validate ban durations
	if config.BanDuration <= 0 {
		return fmt.Errorf("banDuration must be positive")
	}

	if config.RepeatOffenderBanDuration <= config.BanDuration {
		return fmt.Errorf("repeatOffenderBanDuration should be longer than banDuration")
	}

	// Validate global rate limiting settings
	if config.GlobalRateLimit {
		if config.GlobalRequestRate <= 0 {
			return fmt.Errorf("globalRequestRate must be positive when global rate limiting is enabled")
		}

		if config.GlobalRateWindow <= 0 {
			return fmt.Errorf("globalRateWindow must be positive when global rate limiting is enabled")
		}

		if config.GlobalBanDuration <= 0 {
			return fmt.Errorf("globalBanDuration must be positive when global rate limiting is enabled")
		}
	}

	// Validate connection limits
	if config.MaxConcurrentConnections < 0 {
		return fmt.Errorf("maxConcurrentConnections cannot be negative")
	}

	if config.ConnectionRate < 0 {
		return fmt.Errorf("connectionRate cannot be negative")
	}

	if config.MaxRequestsPerConnection < 0 {
		return fmt.Errorf("maxRequestsPerConnection cannot be negative")
	}

	// Validate connection rate window
	if config.ConnectionRateWindow <= 0 {
		return fmt.Errorf("connectionRateWindow must be positive")
	}

	return nil
}
