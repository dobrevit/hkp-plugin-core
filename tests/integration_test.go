package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Test Core Endpoints
func TestCoreEndpoints(t *testing.T) {
	ts := NewTestServer()
	defer ts.Close()

	t.Run("PKS Add", func(t *testing.T) {
		resp, err := ts.Post("/pks/add", map[string]string{
			"keytext": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
		})
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("PKS Lookup", func(t *testing.T) {
		resp, err := ts.Get("/pks/lookup?search=test@example.com")
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "PGP PUBLIC KEY") {
			t.Error("Response should contain PGP key")
		}
	})
}

// Test Zero Trust Plugin
func TestZeroTrustPlugin(t *testing.T) {
	ts := NewTestServer()
	defer ts.Close()

	var sessionID string

	t.Run("ZTNA Status", func(t *testing.T) {
		resp, err := ts.Get("/ztna/status")
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var status map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&status)

		if enabled, ok := status["enabled"].(bool); !ok || !enabled {
			t.Error("ZTNA should be enabled")
		}
	})

	t.Run("ZTNA Login", func(t *testing.T) {
		loginReq := map[string]string{
			"username": "testuser",
			"password": "demo-password-testuser",
		}

		resp, err := ts.Post("/ztna/login", loginReq)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var loginResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&loginResp)

		if status := loginResp["status"].(string); status != "success" && status != "mfa_required" {
			t.Errorf("Expected success or mfa_required, got %s", status)
		}

		if sid, ok := loginResp["session_id"].(string); ok {
			sessionID = sid
		}
	})

	t.Run("ZTNA Device Registration", func(t *testing.T) {
		if sessionID == "" {
			t.Skip("No session ID available")
		}

		deviceReq := map[string]interface{}{
			"platform":          "linux",
			"screen_resolution": "1920x1080",
			"timezone":          "UTC",
		}

		req, _ := http.NewRequest("POST", ts.Server.URL+"/ztna/device",
			bytes.NewReader(mustMarshal(deviceReq)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Cookie", fmt.Sprintf("ztna-session=%s", sessionID))

		resp, err := ts.Client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})
}

// Test ML Abuse Plugin
func TestMLAbusePlugin(t *testing.T) {
	ts := NewTestServer()
	defer ts.Close()

	t.Run("ML Status", func(t *testing.T) {
		resp, err := ts.Get("/api/ml/status")
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("ML Analyze", func(t *testing.T) {
		analyzeReq := map[string]interface{}{
			"request_data": map[string]interface{}{
				"method": "POST",
				"path":   "/api/test",
				"headers": map[string]string{
					"User-Agent": "Mozilla/5.0",
				},
			},
		}

		resp, err := ts.Post("/api/ml/analyze", analyzeReq)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)

		if _, ok := result["is_abuse"]; !ok {
			t.Error("Response should contain is_abuse field")
		}
	})
}

// Test Rate Limit Plugins
func TestRateLimitPlugins(t *testing.T) {
	ts := NewTestServer()
	defer ts.Close()

	t.Run("Threat Intel Status", func(t *testing.T) {
		resp, err := ts.Get("/ratelimit/threatintel/status")
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("Threat Intel Check", func(t *testing.T) {
		checkReq := map[string]string{
			"ip": "192.168.1.100",
		}

		resp, err := ts.Post("/ratelimit/threatintel/check", checkReq)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("Tarpit Status", func(t *testing.T) {
		resp, err := ts.Get("/ratelimit/tarpit/status")
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	t.Run("ML Rate Limit Status", func(t *testing.T) {
		resp, err := ts.Get("/ratelimit/ml/status")
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})
}

// Test Honeypot Paths (Tarpit)
func TestHoneypotPaths(t *testing.T) {
	ts := NewTestServer()
	defer ts.Close()

	honeypotPaths := []string{
		"/admin",
		"/wp-admin",
		"/.git",
		"/.env",
		"/phpmyadmin",
	}

	for _, path := range honeypotPaths {
		t.Run(fmt.Sprintf("Honeypot %s", path), func(t *testing.T) {
			start := time.Now()
			resp, err := ts.Get(path)
			duration := time.Since(start)

			if err != nil {
				// Timeout is expected for tarpit
				if strings.Contains(err.Error(), "timeout") {
					t.Logf("Request to %s timed out as expected (tarpit active)", path)
					return
				}
				t.Fatalf("Unexpected error: %v", err)
			}
			defer resp.Body.Close()

			// If we get a response, it should be delayed
			if duration < 5*time.Second {
				t.Logf("Warning: Honeypot path %s responded quickly (%v), tarpit might not be active", path, duration)
			}
		})
	}
}

// Helper function
func mustMarshal(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
