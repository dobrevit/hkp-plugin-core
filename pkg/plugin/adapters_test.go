package plugin_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/julienschmidt/httprouter"

	"github.com/dobrevit/hkp-plugin-core/pkg/plugin"
)

// TestHTTPHandlerAdapter tests the adapter that converts http.HandlerFunc to httprouter.Handle
func TestHTTPHandlerAdapter(t *testing.T) {
	// Create a standard http.HandlerFunc
	standardHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from standard handler"))
	}

	// Adapt it to httprouter.Handle
	routerHandler := plugin.HTTPHandlerAdapter(standardHandler)

	// Test with httprouter
	router := httprouter.New()
	router.GET("/test", routerHandler)

	// Make a test request
	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Check the response
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := "Hello from standard handler"
	if body := rr.Body.String(); body != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
	}
}

// TestHTTPHandlerWithParamsAdapter tests the adapter that provides access to httprouter params
func TestHTTPHandlerWithParamsAdapter(t *testing.T) {
	// Create a handler that uses httprouter params
	paramsHandler := func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		name := ps.ByName("name")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, " + name))
	}

	// Adapt it (this is basically a no-op but shows the pattern)
	routerHandler := plugin.HTTPHandlerWithParamsAdapter(paramsHandler)

	// Test with httprouter
	router := httprouter.New()
	router.GET("/hello/:name", routerHandler)

	// Make a test request
	req, err := http.NewRequest("GET", "/hello/world", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Check the response
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := "Hello, world"
	if body := rr.Body.String(); body != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
	}
}

// TestWrapStandardHandler tests the convenience wrapper
func TestWrapStandardHandler(t *testing.T) {
	// Create a standard handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"received":"` + string(body) + `"}`))
	})

	// Wrap it
	wrapped := plugin.WrapStandardHandler(handler)

	// Test with httprouter
	router := httprouter.New()
	router.POST("/api/data", wrapped)

	// Make a test request
	reqBody := strings.NewReader("test data")
	req, err := http.NewRequest("POST", "/api/data", reqBody)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Check the response
	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
	}

	if contentType := rr.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("handler returned wrong content type: got %v want %v", contentType, "application/json")
	}

	expected := `{"received":"test data"}`
	if body := rr.Body.String(); body != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", body, expected)
	}
}
