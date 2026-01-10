// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prometheus

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

// TestPrometheusPlugin_PortPriority tests that the plugin prioritizes correct ports
func TestPrometheusPlugin_PortPriority(t *testing.T) {
	plugin := &PrometheusPlugin{}

	tests := []struct {
		name     string
		port     uint16
		expected bool
	}{
		{"Prometheus Server Port", 9090, true},
		{"Pushgateway Port", 9091, true},
		{"Alertmanager Port", 9093, true},
		{"Non-Prometheus Port", 8080, false},
		{"HTTP Port", 80, false},
		{"HTTPS Port", 443, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.PortPriority(tt.port)
			if result != tt.expected {
				t.Errorf("PortPriority(%d) = %v, expected %v", tt.port, result, tt.expected)
			}
		})
	}
}

// TestPrometheusPlugin_Name tests the plugin name
func TestPrometheusPlugin_Name(t *testing.T) {
	plugin := &PrometheusPlugin{}
	if plugin.Name() != "prometheus" {
		t.Errorf("Name() = %s, expected prometheus", plugin.Name())
	}
}

// TestPrometheusPlugin_Type tests the protocol type
func TestPrometheusPlugin_Type(t *testing.T) {
	plugin := &PrometheusPlugin{}
	if plugin.Type() != plugins.TCP {
		t.Errorf("Type() = %v, expected TCP", plugin.Type())
	}
}

// TestPrometheusPlugin_Priority tests the execution priority
func TestPrometheusPlugin_Priority(t *testing.T) {
	plugin := &PrometheusPlugin{}
	priority := plugin.Priority()
	// Should run before generic HTTP (priority 0)
	// Priority -10 to run before generic HTTP
	if priority >= 0 {
		t.Errorf("Priority() = %d, expected < 0 to run before generic HTTP", priority)
	}
	if priority != -10 {
		t.Errorf("Priority() = %d, expected -10", priority)
	}
}

// TestCheckPrometheusBuildInfo tests buildinfo JSON validation
func TestCheckPrometheusBuildInfo(t *testing.T) {
	tests := []struct {
		name        string
		jsonData    string
		expectValid bool
		expectError bool
	}{
		{
			name: "valid prometheus buildinfo response",
			jsonData: `{
				"status": "success",
				"data": {
					"version": "2.48.1",
					"revision": "cb7cbad5f9a2823a622aaa668833ca04f50a0ea7",
					"branch": "HEAD",
					"buildUser": "root@buildkitsandbox",
					"buildDate": "20231213-10:48:17",
					"goVersion": "go1.21.5"
				}
			}`,
			expectValid: true,
			expectError: false,
		},
		{
			name: "valid older version",
			jsonData: `{
				"status": "success",
				"data": {
					"version": "2.45.0",
					"revision": "8ef767e396a0d3d694d9c1813a4c33fea6e55f9e",
					"branch": "HEAD",
					"buildUser": "root@buildkitsandbox",
					"buildDate": "20230615-09:12:34",
					"goVersion": "go1.20.5"
				}
			}`,
			expectValid: true,
			expectError: false,
		},
		{
			name: "missing version field",
			jsonData: `{
				"status": "success",
				"data": {
					"revision": "cb7cbad5f9a2823a622aaa668833ca04f50a0ea7"
				}
			}`,
			expectValid: false,
			expectError: true,
		},
		{
			name: "wrong status field",
			jsonData: `{
				"status": "error",
				"data": {
					"version": "2.48.1"
				}
			}`,
			expectValid: false,
			expectError: true,
		},
		{
			name:        "empty JSON",
			jsonData:    `{}`,
			expectValid: false,
			expectError: true,
		},
		{
			name:        "not JSON",
			jsonData:    `not json`,
			expectValid: false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := checkPrometheusBuildInfo([]byte(tt.jsonData))

			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectValid && result.Data.Version == "" {
				t.Errorf("expected valid version but got empty")
			}
		})
	}
}

// TestExtractSemanticVersion tests semantic version extraction
func TestExtractSemanticVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{"Standard version", "2.48.1", "2.48.1"},
		{"Version with patch", "2.45.0", "2.45.0"},
		{"Old version", "2.40.7", "2.40.7"},
		{"Empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractSemanticVersion(tt.version)
			if result != tt.expected {
				t.Errorf("extractSemanticVersion(%s) = %s, expected %s", tt.version, result, tt.expected)
			}
		})
	}
}

// TestBuildPrometheusCPE tests CPE generation
func TestBuildPrometheusCPE(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expectedCPE string
	}{
		{
			"Version 2.48.1",
			"2.48.1",
			"cpe:2.3:a:prometheus:prometheus:2.48.1:*:*:*:*:*:*:*",
		},
		{
			"Version 2.45.0",
			"2.45.0",
			"cpe:2.3:a:prometheus:prometheus:2.45.0:*:*:*:*:*:*:*",
		},
		{
			"Empty version",
			"",
			"cpe:2.3:a:prometheus:prometheus:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildPrometheusCPE(tt.version)
			if cpe != tt.expectedCPE {
				t.Errorf("buildPrometheusCPE(%s) = %s, expected %s",
					tt.version, cpe, tt.expectedCPE)
			}
		})
	}
}

// TestCheckPrometheusBuildInfo_EdgeCases tests additional edge cases for buildinfo validation
func TestCheckPrometheusBuildInfo_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		jsonData    string
		expectError bool
	}{
		{
			name: "status field not success",
			jsonData: `{
				"status": "error",
				"data": {
					"version": "2.48.1"
				}
			}`,
			expectError: true,
		},
		{
			name: "data object missing",
			jsonData: `{
				"status": "success"
			}`,
			expectError: true,
		},
		{
			name: "version field empty string",
			jsonData: `{
				"status": "success",
				"data": {
					"version": ""
				}
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := checkPrometheusBuildInfo([]byte(tt.jsonData))
			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestParseMetricsForVersion tests parsing version from /metrics endpoint
func TestParseMetricsForVersion(t *testing.T) {
	tests := []struct {
		name           string
		metricsData    string
		expectedVersion string
		expectError    bool
	}{
		{
			name: "valid metrics with version",
			metricsData: `# HELP prometheus_build_info A metric with a constant '1' value labeled by version, revision, branch, and goversion from which prometheus was built.
# TYPE prometheus_build_info gauge
prometheus_build_info{version="2.40.7",revision="11b8a5c0ad3c6697f8e1b2a8e7b0e3b4b2c1d0e1",branch="HEAD",goversion="go1.20.5"} 1
# HELP prometheus_http_requests_total Total number of HTTP requests.
# TYPE prometheus_http_requests_total counter
prometheus_http_requests_total{code="200",handler="/"} 1234`,
			expectedVersion: "2.40.7",
			expectError:    false,
		},
		{
			name: "valid metrics with different version",
			metricsData: `prometheus_build_info{version="2.48.1",revision="cb7cbad5f9a2823a622aaa668833ca04f50a0ea7",branch="HEAD",goversion="go1.21.5"} 1`,
			expectedVersion: "2.48.1",
			expectError:    false,
		},
		{
			name: "metrics without prometheus_build_info",
			metricsData: `# HELP prometheus_http_requests_total Total number of HTTP requests.
# TYPE prometheus_http_requests_total counter
prometheus_http_requests_total{code="200",handler="/"} 1234`,
			expectedVersion: "",
			expectError:    true,
		},
		{
			name: "metrics with prometheus_build_info but no version label",
			metricsData: `prometheus_build_info{revision="cb7cbad5f9a2823a622aaa668833ca04f50a0ea7",branch="HEAD"} 1`,
			expectedVersion: "",
			expectError:    true,
		},
		{
			name:           "empty metrics",
			metricsData:    "",
			expectedVersion: "",
			expectError:    true,
		},
		{
			name: "malformed metrics with version-like string",
			metricsData: `some random text with version="1.2.3" in it`,
			expectedVersion: "",
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := parseMetricsForVersion([]byte(tt.metricsData))

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if version != tt.expectedVersion {
				t.Errorf("parseMetricsForVersion() = %s, expected %s", version, tt.expectedVersion)
			}
		})
	}
}

// TestPrometheusPlugin_Run_WithHeaders tests Run function with header-based detection
func TestPrometheusPlugin_Run_WithHeaders(t *testing.T) {
	// Create test server that returns Prometheus headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return WWW-Authenticate header with Prometheus realm
		w.Header().Set("WWW-Authenticate", `Basic realm="Prometheus"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	// Create connection to test server
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	plugin := &PrometheusPlugin{}
	target := plugins.Target{
		Host: server.Listener.Addr().String(),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if service == nil {
		t.Error("expected service to be detected via headers")
	} else {
		if service.Protocol != "prometheus" {
			t.Errorf("expected protocol 'prometheus', got %s", service.Protocol)
		}
		t.Logf("Service detected: %+v", service)
	}
}

// TestPrometheusPlugin_Run_WithMetricsFallback tests Run function with metrics endpoint fallback
func TestPrometheusPlugin_Run_WithMetricsFallback(t *testing.T) {
	// Create test server that serves metrics but no headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`# HELP prometheus_build_info A metric with a constant '1' value labeled by version, revision, branch, and goversion from which prometheus was built.
# TYPE prometheus_build_info gauge
prometheus_build_info{version="2.40.7",revision="11b8a5c0ad3c6697f8e1b2a8e7b0e3b4b2c1d0e1",branch="HEAD",goversion="go1.20.5"} 1
`))
		} else {
			// Root endpoint returns 200 but no Prometheus headers
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	// Create connection to test server
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	plugin := &PrometheusPlugin{}
	target := plugins.Target{
		Host: server.Listener.Addr().String(),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if service == nil {
		t.Error("expected service to be detected via metrics fallback")
	} else {
		if service.Protocol != "prometheus" {
			t.Errorf("expected protocol 'prometheus', got %s", service.Protocol)
		}
		t.Logf("Service detected with fallback: %+v", service)
	}
}

// TestDetectFromHeaders_WWWAuthenticate tests detection via WWW-Authenticate header
func TestDetectFromHeaders_WWWAuthenticate(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		expectDetected bool
		expectedMethod string
	}{
		{
			name: "WWW-Authenticate with Prometheus realm",
			headers: http.Header{
				"Www-Authenticate": []string{`Basic realm="Prometheus"`},
			},
			expectDetected: true,
			expectedMethod: "www-authenticate-realm",
		},
		{
			name: "WWW-Authenticate with prometheus lowercase",
			headers: http.Header{
				"Www-Authenticate": []string{`Basic realm="prometheus"`},
			},
			expectDetected: true,
			expectedMethod: "www-authenticate-realm",
		},
		{
			name: "WWW-Authenticate with different realm",
			headers: http.Header{
				"Www-Authenticate": []string{`Basic realm="Some Other Service"`},
			},
			expectDetected: false,
		},
		{
			name:           "No WWW-Authenticate header",
			headers:        http.Header{},
			expectDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Header: tt.headers,
			}

			result, detected := detectFromHeaders(resp)

			if detected != tt.expectDetected {
				t.Errorf("detectFromHeaders() detected = %v, expected %v", detected, tt.expectDetected)
			}

			if detected && result.DetectionMethod != tt.expectedMethod {
				t.Errorf("detectFromHeaders() method = %s, expected %s", result.DetectionMethod, tt.expectedMethod)
			}

			if detected && result.Version != "unknown" {
				t.Errorf("detectFromHeaders() version = %s, expected 'unknown' for WWW-Authenticate", result.Version)
			}
		})
	}
}

// TestDetectFromHeaders_ServerHeader tests detection via Server header
func TestDetectFromHeaders_ServerHeader(t *testing.T) {
	tests := []struct {
		name            string
		headers         http.Header
		expectDetected  bool
		expectedVersion string
		expectedMethod  string
	}{
		{
			name: "Server header with version",
			headers: http.Header{
				"Server": []string{"Prometheus/2.40.7"},
			},
			expectDetected:  true,
			expectedVersion: "2.40.7",
			expectedMethod:  "server-header",
		},
		{
			name: "Server header without version",
			headers: http.Header{
				"Server": []string{"Prometheus"},
			},
			expectDetected:  true,
			expectedVersion: "",
			expectedMethod:  "server-header",
		},
		{
			name: "Server header lowercase prometheus",
			headers: http.Header{
				"Server": []string{"prometheus/2.45.0"},
			},
			expectDetected:  true,
			expectedVersion: "2.45.0",
			expectedMethod:  "server-header",
		},
		{
			name: "Server header different service",
			headers: http.Header{
				"Server": []string{"nginx/1.21.0"},
			},
			expectDetected: false,
		},
		{
			name:           "No Server header",
			headers:        http.Header{},
			expectDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Header: tt.headers,
			}

			result, detected := detectFromHeaders(resp)

			if detected != tt.expectDetected {
				t.Errorf("detectFromHeaders() detected = %v, expected %v", detected, tt.expectDetected)
			}

			if detected {
				if result.DetectionMethod != tt.expectedMethod {
					t.Errorf("detectFromHeaders() method = %s, expected %s", result.DetectionMethod, tt.expectedMethod)
				}

				if result.Version != tt.expectedVersion {
					t.Errorf("detectFromHeaders() version = %s, expected %s", result.Version, tt.expectedVersion)
				}
			}
		})
	}
}

// TestExtractVersionFromServer tests version extraction from Server header
func TestExtractVersionFromServer(t *testing.T) {
	tests := []struct {
		name            string
		serverHeader    string
		expectedVersion string
	}{
		{
			name:            "Server with version",
			serverHeader:    "Prometheus/2.40.7",
			expectedVersion: "2.40.7",
		},
		{
			name:            "Server with different version",
			serverHeader:    "Prometheus/2.48.1",
			expectedVersion: "2.48.1",
		},
		{
			name:            "Server without version",
			serverHeader:    "Prometheus",
			expectedVersion: "",
		},
		{
			name:            "Empty server header",
			serverHeader:    "",
			expectedVersion: "",
		},
		{
			name:            "Lowercase prometheus with version",
			serverHeader:    "prometheus/2.45.0",
			expectedVersion: "2.45.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := extractVersionFromServer(tt.serverHeader)

			if version != tt.expectedVersion {
				t.Errorf("extractVersionFromServer(%s) = %s, expected %s", tt.serverHeader, version, tt.expectedVersion)
			}
		})
	}
}
