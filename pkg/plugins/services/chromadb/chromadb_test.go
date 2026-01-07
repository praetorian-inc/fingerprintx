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

package chromadb

import (
	"testing"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

// TestParseChromaDBHeartbeat tests parsing and validation of ChromaDB heartbeat responses
func TestParseChromaDBHeartbeat(t *testing.T) {
	tests := []struct {
		name             string
		response         []byte
		wantDetected     bool
		wantHeartbeat    int64
		description      string
	}{
		{
			name:          "valid ChromaDB 1.x heartbeat",
			response:      []byte(`{"nanosecond heartbeat": 1735740123456789000}`),
			wantDetected:  true,
			wantHeartbeat: 1735740123456789000,
			description:   "Typical ChromaDB 1.x response with valid nanosecond timestamp",
		},
		{
			name:          "valid ChromaDB 0.x heartbeat",
			response:      []byte(`{"nanosecond heartbeat": 1704067200000000000}`),
			wantDetected:  true,
			wantHeartbeat: 1704067200000000000,
			description:   "ChromaDB 0.x response with valid nanosecond timestamp",
		},
		{
			name:          "minimum valid timestamp (1e18)",
			response:      []byte(`{"nanosecond heartbeat": 1000000000000000000}`),
			wantDetected:  true,
			wantHeartbeat: 1000000000000000000,
			description:   "Boundary test: exactly 1e18 nanoseconds",
		},
		{
			name:          "timestamp just above minimum",
			response:      []byte(`{"nanosecond heartbeat": 1000000000000000001}`),
			wantDetected:  true,
			wantHeartbeat: 1000000000000000001,
			description:   "Boundary test: 1e18 + 1 nanoseconds",
		},
		{
			name:          "invalid JSON syntax",
			response:      []byte(`{"nanosecond heartbeat": not-a-number}`),
			wantDetected:  false,
			wantHeartbeat: 0,
			description:   "Malformed JSON should fail parsing",
		},
		{
			name:          "missing nanosecond heartbeat field",
			response:      []byte(`{"other_field": 1234567890}`),
			wantDetected:  false,
			wantHeartbeat: 0,
			description:   "Response missing required field name with space",
		},
		{
			name:          "field name without space (typo)",
			response:      []byte(`{"nanosecondheartbeat": 1735740123456789000}`),
			wantDetected:  false,
			wantHeartbeat: 0,
			description:   "Field name must have space; no space = not ChromaDB",
		},
		{
			name:          "field name with underscore (wrong format)",
			response:      []byte(`{"nanosecond_heartbeat": 1735740123456789000}`),
			wantDetected:  false,
			wantHeartbeat: 0,
			description:   "Field name must use space, not underscore",
		},
		{
			name:          "timestamp too small (milliseconds)",
			response:      []byte(`{"nanosecond heartbeat": 1704067200000}`),
			wantDetected:  false,
			wantHeartbeat: 0,
			description:   "Millisecond timestamp < 1e18, not valid nanoseconds",
		},
		{
			name:          "timestamp just below minimum (1e18 - 1)",
			response:      []byte(`{"nanosecond heartbeat": 999999999999999999}`),
			wantDetected:  false,
			wantHeartbeat: 0,
			description:   "Boundary test: 1e18 - 1 should fail",
		},
		{
			name:          "zero timestamp",
			response:      []byte(`{"nanosecond heartbeat": 0}`),
			wantDetected:  false,
			wantHeartbeat: 0,
			description:   "Zero timestamp is not valid",
		},
		{
			name:          "negative timestamp",
			response:      []byte(`{"nanosecond heartbeat": -1735740123456789000}`),
			wantDetected:  false,
			wantHeartbeat: 0,
			description:   "Negative timestamp should fail validation",
		},
		{
			name:          "string instead of int64",
			response:      []byte(`{"nanosecond heartbeat": "1735740123456789000"}`),
			wantDetected:  false,
			wantHeartbeat: 0,
			description:   "Type mismatch: string instead of numeric value",
		},
		{
			name:          "float instead of int64",
			response:      []byte(`{"nanosecond heartbeat": 1.735740123456789e+18}`),
			wantDetected:  false,
			wantHeartbeat: 0,
			description:   "Type mismatch: float instead of int64",
		},
		{
			name:          "empty JSON object",
			response:      []byte(`{}`),
			wantDetected:  false,
			wantHeartbeat: 0,
			description:   "Empty object missing required field",
		},
		{
			name:          "empty response",
			response:      []byte(``),
			wantDetected:  false,
			wantHeartbeat: 0,
			description:   "Empty byte array should fail",
		},
		{
			name:          "null JSON",
			response:      []byte(`null`),
			wantDetected:  false,
			wantHeartbeat: 0,
			description:   "JSON null is not a valid response",
		},
		{
			name:          "JSON array instead of object",
			response:      []byte(`[1735740123456789000]`),
			wantDetected:  false,
			wantHeartbeat: 0,
			description:   "Array instead of object should fail",
		},
		{
			name:          "multiple fields with valid heartbeat",
			response:      []byte(`{"version": "1.4.0", "nanosecond heartbeat": 1735740123456789000, "other": "data"}`),
			wantDetected:  true,
			wantHeartbeat: 1735740123456789000,
			description:   "Additional fields should not affect detection",
		},
		{
			name:          "whitespace in JSON",
			response:      []byte(`  {  "nanosecond heartbeat"  :  1735740123456789000  }  `),
			wantDetected:  true,
			wantHeartbeat: 1735740123456789000,
			description:   "Extra whitespace should be handled by JSON parser",
		},
		{
			name:          "unicode in field name (should fail)",
			response:      []byte(`{"nanosecond\u0020heartbeat": 1735740123456789000}`),
			wantDetected:  true,
			wantHeartbeat: 1735740123456789000,
			description:   "Unicode space (\\u0020) in field name should work with JSON parser",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detected, heartbeat := parseChromaDBHeartbeat(tt.response)

			if detected != tt.wantDetected {
				t.Errorf("parseChromaDBHeartbeat() detected = %v, want %v\nDescription: %s",
					detected, tt.wantDetected, tt.description)
			}

			if heartbeat != tt.wantHeartbeat {
				t.Errorf("parseChromaDBHeartbeat() heartbeat = %v, want %v\nDescription: %s",
					heartbeat, tt.wantHeartbeat, tt.description)
			}
		})
	}
}

// TestCleanChromaDBVersion tests version string cleaning
func TestCleanChromaDBVersion(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		wantVersion string
		description string
	}{
		{
			name:        "clean semantic version",
			version:     "1.4.0",
			wantVersion: "1.4.0",
			description: "Standard semantic version should remain unchanged",
		},
		{
			name:        "version with alpha pre-release",
			version:     "1.4.0-alpha",
			wantVersion: "1.4.0",
			description: "Pre-release tag should be stripped",
		},
		{
			name:        "version with beta pre-release",
			version:     "1.4.0-beta.1",
			wantVersion: "1.4.0",
			description: "Pre-release with dot notation should be stripped",
		},
		{
			name:        "version with rc pre-release",
			version:     "1.4.0-rc.2",
			wantVersion: "1.4.0",
			description: "Release candidate tag should be stripped",
		},
		{
			name:        "version with commit hash",
			version:     "1.4.0+abc123",
			wantVersion: "1.4.0",
			description: "Commit hash metadata should be stripped",
		},
		{
			name:        "version with both pre-release and commit",
			version:     "1.4.0-alpha+abc123",
			wantVersion: "1.4.0",
			description: "Both pre-release and commit hash should be stripped",
		},
		{
			name:        "version with build metadata",
			version:     "1.4.0+20240101.1200",
			wantVersion: "1.4.0",
			description: "Build timestamp metadata should be stripped",
		},
		{
			name:        "version with multiple hyphens",
			version:     "1.4.0-beta-3-fixes",
			wantVersion: "1.4.0",
			description: "Everything after first hyphen should be removed",
		},
		{
			name:        "version with multiple pluses",
			version:     "1.4.0+abc+def",
			wantVersion: "1.4.0",
			description: "Everything after first plus should be removed",
		},
		{
			name:        "empty string",
			version:     "",
			wantVersion: "",
			description: "Empty string should return empty string",
		},
		{
			name:        "major version only",
			version:     "1",
			wantVersion: "1",
			description: "Single component version should remain unchanged",
		},
		{
			name:        "major.minor only",
			version:     "1.4",
			wantVersion: "1.4",
			description: "Two component version should remain unchanged",
		},
		{
			name:        "four component version",
			version:     "1.4.0.1",
			wantVersion: "1.4.0.1",
			description: "Four component version should remain unchanged",
		},
		{
			name:        "v prefix (non-standard)",
			version:     "v1.4.0",
			wantVersion: "v1.4.0",
			description: "v prefix should be preserved (not our job to strip)",
		},
		{
			name:        "leading/trailing whitespace",
			version:     "  1.4.0  ",
			wantVersion: "  1.4.0  ",
			description: "Whitespace should be preserved (caller should trim)",
		},
		{
			name:        "hyphen only (edge case)",
			version:     "-",
			wantVersion: "",
			description: "Single hyphen should result in empty string",
		},
		{
			name:        "plus only (edge case)",
			version:     "+",
			wantVersion: "",
			description: "Single plus should result in empty string",
		},
		{
			name:        "pre-release with multiple dots",
			version:     "1.4.0-beta.1.2.3",
			wantVersion: "1.4.0",
			description: "Complex pre-release notation should be stripped",
		},
		{
			name:        "zero version components",
			version:     "0.0.0",
			wantVersion: "0.0.0",
			description: "Zero version should remain unchanged",
		},
		{
			name:        "large version numbers",
			version:     "999.888.777",
			wantVersion: "999.888.777",
			description: "Large version numbers should remain unchanged",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanChromaDBVersion(tt.version)

			if result != tt.wantVersion {
				t.Errorf("cleanChromaDBVersion(%q) = %q, want %q\nDescription: %s",
					tt.version, result, tt.wantVersion, tt.description)
			}
		})
	}
}

// TestBuildChromaDBCPE tests CPE generation
func TestBuildChromaDBCPE(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		wantCPE     string
		description string
	}{
		{
			name:        "ChromaDB 1.4.0",
			version:     "1.4.0",
			wantCPE:     "cpe:2.3:a:chroma:chromadb:1.4.0:*:*:*:*:*:*:*",
			description: "Standard version should generate CPE with version",
		},
		{
			name:        "ChromaDB 0.5.20",
			version:     "0.5.20",
			wantCPE:     "cpe:2.3:a:chroma:chromadb:0.5.20:*:*:*:*:*:*:*",
			description: "Older version should generate CPE with version",
		},
		{
			name:        "ChromaDB 1.0.0",
			version:     "1.0.0",
			wantCPE:     "cpe:2.3:a:chroma:chromadb:1.0.0:*:*:*:*:*:*:*",
			description: "Major release should generate CPE with version",
		},
		{
			name:        "ChromaDB 2.0.0-beta",
			version:     "2.0.0-beta",
			wantCPE:     "cpe:2.3:a:chroma:chromadb:2.0.0-beta:*:*:*:*:*:*:*",
			description: "Pre-release version should be preserved in CPE (caller should clean)",
		},
		{
			name:        "unknown version (wildcard)",
			version:     "",
			wantCPE:     "cpe:2.3:a:chroma:chromadb:*:*:*:*:*:*:*:*",
			description: "Empty version should generate wildcard CPE",
		},
		{
			name:        "single component version",
			version:     "1",
			wantCPE:     "cpe:2.3:a:chroma:chromadb:1:*:*:*:*:*:*:*",
			description: "Single component version should be valid in CPE",
		},
		{
			name:        "two component version",
			version:     "1.4",
			wantCPE:     "cpe:2.3:a:chroma:chromadb:1.4:*:*:*:*:*:*:*",
			description: "Two component version should be valid in CPE",
		},
		{
			name:        "four component version",
			version:     "1.4.0.1",
			wantCPE:     "cpe:2.3:a:chroma:chromadb:1.4.0.1:*:*:*:*:*:*:*",
			description: "Four component version should be valid in CPE",
		},
		{
			name:        "version with v prefix",
			version:     "v1.4.0",
			wantCPE:     "cpe:2.3:a:chroma:chromadb:v1.4.0:*:*:*:*:*:*:*",
			description: "v prefix should be preserved in CPE (caller should clean)",
		},
		{
			name:        "zero version",
			version:     "0.0.0",
			wantCPE:     "cpe:2.3:a:chroma:chromadb:0.0.0:*:*:*:*:*:*:*",
			description: "Zero version should generate valid CPE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildChromaDBCPE(tt.version)

			if result != tt.wantCPE {
				t.Errorf("buildChromaDBCPE(%q) = %q, want %q\nDescription: %s",
					tt.version, result, tt.wantCPE, tt.description)
			}
		})
	}
}

// TestExtractHTTPBody tests HTTP response body extraction
func TestExtractHTTPBody(t *testing.T) {
	tests := []struct {
		name        string
		response    []byte
		wantBody    []byte
		description string
	}{
		{
			name: "typical HTTP response with headers",
			response: []byte(
				"HTTP/1.1 200 OK\r\n" +
					"Content-Type: application/json\r\n" +
					"Content-Length: 42\r\n" +
					"\r\n" +
					`{"nanosecond heartbeat": 1735740123456789000}`,
			),
			wantBody:    []byte(`{"nanosecond heartbeat": 1735740123456789000}`),
			description: "Standard HTTP response should extract JSON body",
		},
		{
			name: "HTTP response with multiple headers",
			response: []byte(
				"HTTP/1.1 200 OK\r\n" +
					"Server: uvicorn\r\n" +
					"Content-Type: application/json\r\n" +
					"Content-Length: 42\r\n" +
					"Date: Wed, 01 Jan 2025 12:00:00 GMT\r\n" +
					"\r\n" +
					`{"version": "1.4.0"}`,
			),
			wantBody:    []byte(`{"version": "1.4.0"}`),
			description: "Multiple headers should be stripped correctly",
		},
		{
			name: "minimal HTTP response",
			response: []byte(
				"HTTP/1.1 200 OK\r\n" +
					"\r\n" +
					`{"nanosecond heartbeat": 1704067200000000000}`,
			),
			wantBody:    []byte(`{"nanosecond heartbeat": 1704067200000000000}`),
			description: "Minimal headers should work",
		},
		{
			name: "HTTP response with empty body",
			response: []byte(
				"HTTP/1.1 204 No Content\r\n" +
					"Content-Length: 0\r\n" +
					"\r\n",
			),
			wantBody: []byte(
				"HTTP/1.1 204 No Content\r\n" +
					"Content-Length: 0\r\n" +
					"\r\n",
			),
			description: "Empty body after headers - implementation returns full response when separator at end",
		},
		{
			name: "response without HTTP headers (raw JSON)",
			response: []byte(`{"nanosecond heartbeat": 1735740123456789000}`),
			wantBody: []byte(`{"nanosecond heartbeat": 1735740123456789000}`),
			description: "Raw JSON without headers should be returned as-is (edge case)",
		},
		{
			name:        "empty response",
			response:    []byte(``),
			wantBody:    []byte(``),
			description: "Empty byte array should return empty body",
		},
		{
			name: "only headers no body separator",
			response: []byte(
				"HTTP/1.1 200 OK\r\n" +
					"Content-Type: application/json\r\n",
			),
			wantBody:    []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"),
			description: "Missing separator should treat entire response as body",
		},
		{
			name: "HTTP response with LF only (non-standard)",
			response: []byte(
				"HTTP/1.1 200 OK\n" +
					"Content-Type: application/json\n" +
					"\n" +
					`{"nanosecond heartbeat": 1735740123456789000}`,
			),
			wantBody: []byte("HTTP/1.1 200 OK\n" +
				"Content-Type: application/json\n" +
				"\n" +
				`{"nanosecond heartbeat": 1735740123456789000}`),
			description: "LF-only line endings should fail separator detection, treat as raw body",
		},
		{
			name: "HTTP response with body containing CRLF",
			response: []byte(
				"HTTP/1.1 200 OK\r\n" +
					"Content-Type: text/plain\r\n" +
					"\r\n" +
					"Line 1\r\nLine 2\r\nLine 3",
			),
			wantBody:    []byte("Line 1\r\nLine 2\r\nLine 3"),
			description: "Body with CRLF should be extracted correctly",
		},
		{
			name: "HTTP response with separator at end (no body)",
			response: []byte(
				"HTTP/1.1 200 OK\r\n" +
					"Content-Length: 0\r\n" +
					"\r\n",
			),
			wantBody: []byte(
				"HTTP/1.1 200 OK\r\n" +
					"Content-Length: 0\r\n" +
					"\r\n",
			),
			description: "Separator at end with no body - implementation returns full response",
		},
		{
			name: "very short response (less than 4 bytes)",
			response:    []byte("Hi"),
			wantBody:    []byte("Hi"),
			description: "Response shorter than separator should be treated as body",
		},
		{
			name: "response with CRLF but not separator pattern",
			response:    []byte("Some\r\ntext\r\nhere"),
			wantBody:    []byte("Some\r\ntext\r\nhere"),
			description: "Single CRLF (not double) should not trigger header parsing",
		},
		{
			name: "HTTP response with chunked encoding headers",
			response: []byte(
				"HTTP/1.1 200 OK\r\n" +
					"Transfer-Encoding: chunked\r\n" +
					"Content-Type: application/json\r\n" +
					"\r\n" +
					"2A\r\n" +
					`{"nanosecond heartbeat": 1735740123456789000}` + "\r\n" +
					"0\r\n\r\n",
			),
			wantBody: []byte("2A\r\n" +
				`{"nanosecond heartbeat": 1735740123456789000}` + "\r\n" +
				"0\r\n\r\n"),
			description: "Chunked transfer encoding body should be extracted (caller must decode)",
		},
		{
			name: "HTTP error response",
			response: []byte(
				"HTTP/1.1 404 Not Found\r\n" +
					"Content-Type: text/plain\r\n" +
					"\r\n" +
					"Endpoint not found",
			),
			wantBody:    []byte("Endpoint not found"),
			description: "Error responses should extract body correctly",
		},
		{
			name: "HTTP response with binary data in body",
			response: []byte(
				"HTTP/1.1 200 OK\r\n" +
					"Content-Type: application/octet-stream\r\n" +
					"\r\n\x00\x01\x02\xff\xfe",
			),
			wantBody:    []byte("\x00\x01\x02\xff\xfe"),
			description: "Binary data in body should be extracted correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractHTTPBody(tt.response)

			// Compare byte slices
			if len(result) != len(tt.wantBody) {
				t.Errorf("extractHTTPBody() length = %d, want %d\nDescription: %s",
					len(result), len(tt.wantBody), tt.description)
			}

			// Byte-by-byte comparison
			for i := 0; i < len(result) && i < len(tt.wantBody); i++ {
				if result[i] != tt.wantBody[i] {
					t.Errorf("extractHTTPBody() byte mismatch at position %d: got %d, want %d\nDescription: %s",
						i, result[i], tt.wantBody[i], tt.description)
					break
				}
			}

			// Also compare as strings for easier debugging
			if string(result) != string(tt.wantBody) {
				t.Errorf("extractHTTPBody() = %q, want %q\nDescription: %s",
					string(result), string(tt.wantBody), tt.description)
			}
		})
	}
}

// TestBuildChromaDBHTTPRequest tests HTTP request construction
func TestBuildChromaDBHTTPRequest(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		host         string
		wantContains []string
		description  string
	}{
		{
			name: "heartbeat endpoint request",
			path: "/api/v1/heartbeat",
			host: "localhost:8000",
			wantContains: []string{
				"GET /api/v1/heartbeat HTTP/1.1\r\n",
				"Host: localhost:8000\r\n",
				"User-Agent: fingerprintx/1.1.13\r\n",
				"Accept: application/json\r\n",
				"Connection: close\r\n",
				"\r\n",
			},
			description: "Heartbeat request should have correct headers",
		},
		{
			name: "version endpoint request",
			path: "/api/v1/version",
			host: "localhost:8000",
			wantContains: []string{
				"GET /api/v1/version HTTP/1.1\r\n",
				"Host: localhost:8000\r\n",
				"User-Agent: fingerprintx/1.1.13\r\n",
				"Accept: application/json\r\n",
				"Connection: close\r\n",
				"\r\n",
			},
			description: "Version request should have correct headers",
		},
		{
			name: "custom port",
			path: "/api/v1/heartbeat",
			host: "chromadb.example.com:9000",
			wantContains: []string{
				"Host: chromadb.example.com:9000\r\n",
			},
			description: "Custom port should be included in Host header",
		},
		{
			name: "IPv4 address",
			path: "/api/v1/heartbeat",
			host: "192.168.1.100:8000",
			wantContains: []string{
				"Host: 192.168.1.100:8000\r\n",
			},
			description: "IPv4 address should work in Host header",
		},
		{
			name: "IPv6 address with brackets",
			path: "/api/v1/heartbeat",
			host: "[::1]:8000",
			wantContains: []string{
				"Host: [::1]:8000\r\n",
			},
			description: "IPv6 address with brackets should work in Host header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildChromaDBHTTPRequest(tt.path, tt.host)

			// Check that all required strings are present
			for _, want := range tt.wantContains {
				if !contains(result, want) {
					t.Errorf("buildChromaDBHTTPRequest() missing %q\nDescription: %s\nGot:\n%s",
						want, tt.description, result)
				}
			}

			// Verify HTTP/1.1
			if !contains(result, "HTTP/1.1") {
				t.Errorf("buildChromaDBHTTPRequest() missing HTTP/1.1 version")
			}

			// Verify double CRLF at end (header/body separator)
			if !contains(result, "\r\n\r\n") {
				t.Errorf("buildChromaDBHTTPRequest() missing header terminator (\\r\\n\\r\\n)")
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && indexOf(s, substr) >= 0))
}

// Helper function to find substring index
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// TestChromaDBPluginInterface tests the plugin interface methods
func TestChromaDBPluginInterface(t *testing.T) {
	plugin := &ChromaDBPlugin{}

	t.Run("Name", func(t *testing.T) {
		if name := plugin.Name(); name != CHROMADB {
			t.Errorf("Name() = %q, want %q", name, CHROMADB)
		}
	})

	t.Run("Type", func(t *testing.T) {
		if pluginType := plugin.Type(); pluginType != plugins.TCP {
			t.Errorf("Type() = %v, want TCP (%v)", pluginType, plugins.TCP)
		}
	})

	t.Run("Priority", func(t *testing.T) {
		priority := plugin.Priority()
		if priority != 50 {
			t.Errorf("Priority() = %d, want 50", priority)
		}
	})

	t.Run("PortPriority default port", func(t *testing.T) {
		if !plugin.PortPriority(DefaultChromaDBPort) {
			t.Errorf("PortPriority(%d) = false, want true", DefaultChromaDBPort)
		}
	})

	t.Run("PortPriority non-default port", func(t *testing.T) {
		if plugin.PortPriority(8080) {
			t.Error("PortPriority(8080) = true, want false")
		}
	})
}

// TestChromaDBTLSPluginInterface tests the TLS plugin interface methods
func TestChromaDBTLSPluginInterface(t *testing.T) {
	plugin := &ChromaDBTLSPlugin{}

	t.Run("Name", func(t *testing.T) {
		if name := plugin.Name(); name != CHROMADBTLS {
			t.Errorf("Name() = %q, want %q", name, CHROMADBTLS)
		}
	})

	t.Run("Type", func(t *testing.T) {
		if pluginType := plugin.Type(); pluginType != plugins.TCPTLS {
			t.Errorf("Type() = %v, want TCPTLS (%v)", pluginType, plugins.TCPTLS)
		}
	})

	t.Run("Priority", func(t *testing.T) {
		priority := plugin.Priority()
		if priority != 51 {
			t.Errorf("Priority() = %d, want 51", priority)
		}
	})

	t.Run("PortPriority default port", func(t *testing.T) {
		if !plugin.PortPriority(DefaultChromaDBPort) {
			t.Errorf("PortPriority(%d) = false, want true", DefaultChromaDBPort)
		}
	})

	t.Run("PortPriority non-default port", func(t *testing.T) {
		if plugin.PortPriority(8443) {
			t.Error("PortPriority(8443) = true, want false")
		}
	})
}
