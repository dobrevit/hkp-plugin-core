package tests

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// AssertStatus checks if the response has the expected status code
func AssertStatus(t *testing.T, expected, actual int) {
	t.Helper()
	if expected != actual {
		t.Errorf("Expected status %d, got %d", expected, actual)
	}
}

// AssertJSONResponse checks if response contains expected JSON fields
func AssertJSONResponse(t *testing.T, resp *http.Response, expectedFields map[string]interface{}) {
	t.Helper()
	
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}
	
	for key, expectedValue := range expectedFields {
		actualValue, exists := result[key]
		if !exists {
			t.Errorf("Expected field '%s' not found in response", key)
			continue
		}
		
		if expectedValue != nil && actualValue != expectedValue {
			t.Errorf("Field '%s': expected %v, got %v", key, expectedValue, actualValue)
		}
	}
}

// AssertResponseContains checks if response body contains expected string
func AssertResponseContains(t *testing.T, resp *http.Response, expected string) {
	t.Helper()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	
	if !strings.Contains(string(body), expected) {
		t.Errorf("Response does not contain expected string: %s\nActual: %s", expected, string(body))
	}
}

// AssertNoError checks that error is nil
func AssertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

// WaitForCondition waits for a condition to be true
func WaitForCondition(t *testing.T, condition func() bool, timeout time.Duration, message string) {
	t.Helper()
	
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	
	t.Fatalf("Condition not met within %v: %s", timeout, message)
}

// MockRequest creates a mock HTTP request for testing
type MockRequest struct {
	Method  string
	Path    string
	Headers map[string]string
	Body    interface{}
}

// ToHTTPRequest converts MockRequest to http.Request
func (mr *MockRequest) ToHTTPRequest() (*http.Request, error) {
	var bodyReader io.Reader
	if mr.Body != nil {
		jsonBody, err := json.Marshal(mr.Body)
		if err != nil {
			return nil, err
		}
		bodyReader = strings.NewReader(string(jsonBody))
	}
	
	req, err := http.NewRequest(mr.Method, mr.Path, bodyReader)
	if err != nil {
		return nil, err
	}
	
	for key, value := range mr.Headers {
		req.Header.Set(key, value)
	}
	
	if mr.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	
	return req, nil
}

// TestScenario represents a test scenario
type TestScenario struct {
	Name           string
	Request        MockRequest
	ExpectedStatus int
	ExpectedFields map[string]interface{}
	ExpectedError  bool
}

// RunTestScenarios runs multiple test scenarios
func RunTestScenarios(t *testing.T, ts *TestServer, scenarios []TestScenario) {
	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			req, err := scenario.Request.ToHTTPRequest()
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			
			// Prepend server URL
			req.URL.Scheme = "http"
			req.URL.Host = ts.Server.URL[7:] // Remove "http://"
			
			resp, err := ts.Client.Do(req)
			if scenario.ExpectedError && err != nil {
				// Error was expected
				return
			}
			
			AssertNoError(t, err)
			defer resp.Body.Close()
			
			AssertStatus(t, scenario.ExpectedStatus, resp.StatusCode)
			
			if scenario.ExpectedFields != nil {
				AssertJSONResponse(t, resp, scenario.ExpectedFields)
			}
		})
	}
}