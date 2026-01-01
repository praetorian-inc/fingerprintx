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

package couchdb

import (
	"testing"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/stretchr/testify/assert"
)

// TestParseCouchDBResponse tests parsing of CouchDB root endpoint JSON responses
func TestParseCouchDBResponse(t *testing.T) {
	tests := []struct {
		name            string
		response        string
		expectDetected  bool
		expectedVersion string
	}{
		{
			name: "valid_couchdb_3.4.2_response",
			response: `{
				"couchdb": "Welcome",
				"version": "3.4.2",
				"git_sha": "6e5ad2a5c",
				"uuid": "9ddf59457dbb8772316cf06fc5e5a2e4",
				"features": ["access-ready", "partitioned"],
				"vendor": {"name": "The Apache Software Foundation"}
			}`,
			expectDetected:  true,
			expectedVersion: "3.4.2",
		},
		{
			name: "valid_couchdb_2.3.1_response",
			response: `{
				"couchdb": "Welcome",
				"version": "2.3.1",
				"git_sha": "c298091a4",
				"uuid": "85fb71bf700c17267fef77535820e371",
				"features": ["scheduler"],
				"vendor": {"name": "The Apache Software Foundation"}
			}`,
			expectDetected:  true,
			expectedVersion: "2.3.1",
		},
		{
			name: "valid_couchdb_1.6.1_response_no_features",
			response: `{
				"couchdb": "Welcome",
				"version": "1.6.1",
				"uuid": "85fb71bf700c17267fef77535820e371",
				"vendor": {"name": "The Apache Software Foundation"}
			}`,
			expectDetected:  true,
			expectedVersion: "1.6.1",
		},
		{
			name: "couchdb_detected_but_no_version",
			response: `{
				"couchdb": "Welcome",
				"uuid": "85fb71bf700c17267fef77535820e371",
				"vendor": {"name": "The Apache Software Foundation"}
			}`,
			expectDetected:  true,
			expectedVersion: "",
		},
		{
			name: "invalid_missing_couchdb_field",
			response: `{
				"version": "3.4.2",
				"vendor": {"name": "The Apache Software Foundation"}
			}`,
			expectDetected:  false,
			expectedVersion: "",
		},
		{
			name: "invalid_wrong_couchdb_value",
			response: `{
				"couchdb": "NotWelcome",
				"version": "3.4.2",
				"vendor": {"name": "The Apache Software Foundation"}
			}`,
			expectDetected:  false,
			expectedVersion: "",
		},
		{
			name: "invalid_missing_vendor",
			response: `{
				"couchdb": "Welcome",
				"version": "3.4.2"
			}`,
			expectDetected:  false,
			expectedVersion: "",
		},
		{
			name:            "invalid_empty_json",
			response:        `{}`,
			expectDetected:  false,
			expectedVersion: "",
		},
		{
			name:            "invalid_not_json",
			response:        `This is not JSON`,
			expectDetected:  false,
			expectedVersion: "",
		},
		{
			name:            "invalid_empty_response",
			response:        ``,
			expectDetected:  false,
			expectedVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detected, version := parseCouchDBResponse([]byte(tt.response))
			assert.Equal(t, tt.expectDetected, detected, "Detection result mismatch")
			assert.Equal(t, tt.expectedVersion, version, "Version extraction mismatch")
		})
	}
}

// TestBuildCouchDBCPE tests CPE generation for CouchDB
func TestBuildCouchDBCPE(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expectedCPE string
	}{
		{
			name:        "couchdb_3.4.2_with_version",
			version:     "3.4.2",
			expectedCPE: "cpe:2.3:a:apache:couchdb:3.4.2:*:*:*:*:*:*:*",
		},
		{
			name:        "couchdb_2.3.1_with_version",
			version:     "2.3.1",
			expectedCPE: "cpe:2.3:a:apache:couchdb:2.3.1:*:*:*:*:*:*:*",
		},
		{
			name:        "couchdb_unknown_version_wildcard",
			version:     "",
			expectedCPE: "cpe:2.3:a:apache:couchdb:*:*:*:*:*:*:*:*",
		},
		{
			name:        "couchdb_1.6.1_legacy_version",
			version:     "1.6.1",
			expectedCPE: "cpe:2.3:a:apache:couchdb:1.6.1:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildCouchDBCPE(tt.version)
			assert.Equal(t, tt.expectedCPE, cpe)
		})
	}
}

// TestBuildCouchDBHTTPRequest tests HTTP request building
func TestBuildCouchDBHTTPRequest(t *testing.T) {
	request := buildCouchDBHTTPRequest("/", "localhost:5984")

	// Verify request structure
	assert.Contains(t, request, "GET / HTTP/1.1\r\n")
	assert.Contains(t, request, "Host: localhost:5984\r\n")
	assert.Contains(t, request, "User-Agent: fingerprintx/1.1.13\r\n")
	assert.Contains(t, request, "Accept: application/json\r\n")
	assert.Contains(t, request, "\r\n\r\n") // Headers end
}

// TestHTTPResponseParsing tests parsing HTTP responses with headers
func TestHTTPResponseParsing(t *testing.T) {
	tests := []struct {
		name            string
		httpResponse    string
		expectDetected  bool
		expectedVersion string
	}{
		{
			name: "valid_http_response_with_headers",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"Server: CouchDB/3.4.2 (Erlang OTP/25)\r\n" +
				"\r\n" +
				`{"couchdb":"Welcome","version":"3.4.2","vendor":{"name":"The Apache Software Foundation"}}`,
			expectDetected:  true,
			expectedVersion: "3.4.2",
		},
		{
			name: "valid_http_response_minimal_headers",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n" +
				`{"couchdb":"Welcome","version":"2.3.1","vendor":{"name":"The Apache Software Foundation"}}`,
			expectDetected:  true,
			expectedVersion: "2.3.1",
		},
		{
			name: "invalid_http_response_not_couchdb",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n" +
				`{"server":"NotCouchDB","version":"1.0.0"}`,
			expectDetected:  false,
			expectedVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Extract body from HTTP response (same logic as detectCouchDB)
			response := []byte(tt.httpResponse)
			bodyStart := 0
			for i := 0; i < len(response)-3; i++ {
				if response[i] == '\r' && response[i+1] == '\n' && response[i+2] == '\r' && response[i+3] == '\n' {
					bodyStart = i + 4
					break
				}
			}

			var jsonBody []byte
			if bodyStart > 0 && bodyStart < len(response) {
				jsonBody = response[bodyStart:]
			} else {
				jsonBody = response
			}

			detected, version := parseCouchDBResponse(jsonBody)
			assert.Equal(t, tt.expectDetected, detected, "Detection result mismatch")
			assert.Equal(t, tt.expectedVersion, version, "Version extraction mismatch")
		})
	}
}

// TestPluginMetadata tests plugin metadata methods
func TestPluginMetadata(t *testing.T) {
	plugin := &COUCHDBPlugin{}

	// Test Name
	assert.Equal(t, "couchdb", plugin.Name())

	// Test Type
	assert.Equal(t, plugins.TCP, plugin.Type())

	// Test Priority
	assert.Equal(t, 100, plugin.Priority())

	// Test PortPriority
	assert.True(t, plugin.PortPriority(5984), "Port 5984 should be prioritized")
	assert.False(t, plugin.PortPriority(8080), "Port 8080 should not be prioritized")
	assert.False(t, plugin.PortPriority(80), "Port 80 should not be prioritized")
}

// TestTLSPluginMetadata tests TLS plugin metadata methods
func TestTLSPluginMetadata(t *testing.T) {
	plugin := &COUCHDBTLSPlugin{}

	// Test Name
	assert.Equal(t, "couchdb", plugin.Name())

	// Test Type
	assert.Equal(t, plugins.TCPTLS, plugin.Type())

	// Test Priority
	assert.Equal(t, 101, plugin.Priority())

	// Test PortPriority
	assert.True(t, plugin.PortPriority(6984), "Port 6984 should be prioritized")
	assert.False(t, plugin.PortPriority(5984), "Port 5984 should not be prioritized")
	assert.False(t, plugin.PortPriority(8080), "Port 8080 should not be prioritized")
	assert.False(t, plugin.PortPriority(80), "Port 80 should not be prioritized")
}

// TestPluginsDifferentPorts verifies plain and TLS plugins use different ports
func TestPluginsDifferentPorts(t *testing.T) {
	plainPlugin := &COUCHDBPlugin{}
	tlsPlugin := &COUCHDBTLSPlugin{}

	// Verify plain plugin prioritizes 5984, not 6984
	assert.True(t, plainPlugin.PortPriority(5984), "Plain plugin should prioritize port 5984")
	assert.False(t, plainPlugin.PortPriority(6984), "Plain plugin should NOT prioritize port 6984")

	// Verify TLS plugin prioritizes 6984, not 5984
	assert.True(t, tlsPlugin.PortPriority(6984), "TLS plugin should prioritize port 6984")
	assert.False(t, tlsPlugin.PortPriority(5984), "TLS plugin should NOT prioritize port 5984")

	// Verify different transport types
	assert.Equal(t, plugins.TCP, plainPlugin.Type(), "Plain plugin should use TCP transport")
	assert.Equal(t, plugins.TCPTLS, tlsPlugin.Type(), "TLS plugin should use TCPTLS transport")
}

// TestEdgeCases tests edge cases in parsing
func TestEdgeCases(t *testing.T) {
	tests := []struct {
		name            string
		response        string
		expectDetected  bool
		expectedVersion string
	}{
		{
			name: "vendor_field_empty_string",
			response: `{
				"couchdb": "Welcome",
				"version": "3.4.2",
				"vendor": {"name": ""}
			}`,
			expectDetected:  false, // Empty vendor.name should fail
			expectedVersion: "",
		},
		{
			name: "vendor_field_different_value",
			response: `{
				"couchdb": "Welcome",
				"version": "3.4.2",
				"vendor": {"name": "Custom Vendor"}
			}`,
			expectDetected:  true, // Different vendor name should still work (fork scenario)
			expectedVersion: "3.4.2",
		},
		{
			name: "version_field_empty_string",
			response: `{
				"couchdb": "Welcome",
				"version": "",
				"vendor": {"name": "The Apache Software Foundation"}
			}`,
			expectDetected:  true,
			expectedVersion: "",
		},
		{
			name: "extra_fields_present",
			response: `{
				"couchdb": "Welcome",
				"version": "3.4.2",
				"git_sha": "6e5ad2a5c",
				"uuid": "test-uuid",
				"features": ["feature1", "feature2"],
				"vendor": {"name": "The Apache Software Foundation"},
				"extra_field": "ignored"
			}`,
			expectDetected:  true,
			expectedVersion: "3.4.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detected, version := parseCouchDBResponse([]byte(tt.response))
			assert.Equal(t, tt.expectDetected, detected, "Detection result mismatch")
			assert.Equal(t, tt.expectedVersion, version, "Version extraction mismatch")
		})
	}
}
