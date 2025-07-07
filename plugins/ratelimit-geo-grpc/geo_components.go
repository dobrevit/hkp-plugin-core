// Geographic analysis components
package main

import (
	"time"
)

// Travel violation represents an impossible travel detection
type TravelViolation struct {
	FromCity  string
	ToCity    string
	Distance  float64
	TimeDelta time.Duration
	Speed     float64
}

// GeographicCluster represents detected clustering
type GeographicCluster struct {
	CenterCity string
	Radius     float64
	Size       int
	IPs        []string
}

// NewLocationTracker creates a new location tracker
func NewLocationTracker() *LocationTracker {
	return &LocationTracker{
		locations: make(map[string][]*GeoLocation),
	}
}

// TrackLocation tracks a new location for an IP
func (lt *LocationTracker) TrackLocation(ip string, location *GeoLocation) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	locations := lt.locations[ip]
	locations = append(locations, location)

	// Keep only the most recent locations (configurable limit)
	maxLocations := 50
	if len(locations) > maxLocations {
		locations = locations[len(locations)-maxLocations:]
	}

	lt.locations[ip] = locations
}

// GetLocations returns all tracked locations for an IP
func (lt *LocationTracker) GetLocations(ip string) []*GeoLocation {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	locations, exists := lt.locations[ip]
	if !exists {
		return nil
	}

	// Return a copy to avoid race conditions
	result := make([]*GeoLocation, len(locations))
	copy(result, locations)
	return result
}

// GetLocationCount returns the number of tracked IPs
func (lt *LocationTracker) GetLocationCount() int {
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	return len(lt.locations)
}

// CleanupOldLocations removes old location data
func (lt *LocationTracker) CleanupOldLocations(maxAge time.Duration) int {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	cleaned := 0

	for ip, locations := range lt.locations {
		filteredLocations := make([]*GeoLocation, 0)

		for _, location := range locations {
			if location.Timestamp.After(cutoff) {
				filteredLocations = append(filteredLocations, location)
			} else {
				cleaned++
			}
		}

		if len(filteredLocations) == 0 {
			delete(lt.locations, ip)
		} else {
			lt.locations[ip] = filteredLocations
		}
	}

	return cleaned
}

// NewTravelAnalyzer creates a new travel analyzer
func NewTravelAnalyzer(config *GeoConfig) *TravelAnalyzer {
	return &TravelAnalyzer{
		config: config,
	}
}

// AnalyzeTravel analyzes travel patterns for impossible travel
func (ta *TravelAnalyzer) AnalyzeTravel(ip string, currentLocation *GeoLocation, locationHistory []*GeoLocation) *TravelViolation {
	if len(locationHistory) < 2 {
		return nil
	}

	// Check the most recent travel
	previousLocation := locationHistory[len(locationHistory)-2]

	// Calculate distance between locations
	plugin := &GeoRateLimitPlugin{config: ta.config}
	distance := plugin.calculateDistance(
		previousLocation.Latitude, previousLocation.Longitude,
		currentLocation.Latitude, currentLocation.Longitude,
	)

	// Calculate time difference
	timeDelta := currentLocation.Timestamp.Sub(previousLocation.Timestamp)

	// Ignore very short time deltas (same minute)
	if timeDelta < time.Minute {
		return nil
	}

	// Calculate speed in km/h
	speed := distance / timeDelta.Hours()

	// Check if speed exceeds reasonable limits
	if speed > ta.config.MaxTravelSpeed {
		return &TravelViolation{
			FromCity:  previousLocation.City,
			ToCity:    currentLocation.City,
			Distance:  distance,
			TimeDelta: timeDelta,
			Speed:     speed,
		}
	}

	return nil
}

// NewClusterDetector creates a new cluster detector
func NewClusterDetector(config *GeoConfig) *ClusterDetector {
	return &ClusterDetector{
		config: config,
	}
}

// DetectClustering detects suspicious geographic clustering
func (cd *ClusterDetector) DetectClustering(location *GeoLocation) *GeographicCluster {
	// Simplified clustering detection
	// In a real implementation, this would analyze patterns across multiple IPs

	// For demo purposes, we'll simulate clustering detection based on location
	// This would normally require tracking multiple IPs and their locations

	// Simulate detection based on certain geographic regions
	if location.Country == "Unknown" && location.City == "Unknown" {
		// Simulate a cluster detection for unknown locations
		return &GeographicCluster{
			CenterCity: "Unknown Region",
			Radius:     cd.config.ClusterRadius,
			Size:       cd.config.ClusterSizeThreshold + 1,
			IPs:        []string{"simulated cluster"},
		}
	}

	return nil
}
