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

package elasticsearch

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCleanVersionString tests version string cleanup (removing -SNAPSHOT suffix)
func TestCleanVersionString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard_version", "8.11.3", "8.11.3"},
		{"snapshot_version", "8.11.3-SNAPSHOT", "8.11.3"},
		{"rc_version", "8.0.0-rc2", "8.0.0-rc2"},
		{"old_version", "7.17.16", "7.17.16"},
		{"empty_version", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanVersionString(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestBuildElasticsearchCPE tests CPE generation for Elasticsearch
func TestBuildElasticsearchCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "with_version",
			version:  "8.11.3",
			expected: "cpe:2.3:a:elastic:elasticsearch:8.11.3:*:*:*:*:*:*:*",
		},
		{
			name:     "with_rc_version",
			version:  "8.0.0-rc2",
			expected: "cpe:2.3:a:elastic:elasticsearch:8.0.0-rc2:*:*:*:*:*:*:*",
		},
		{
			name:     "empty_version_uses_wildcard",
			version:  "",
			expected: "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*",
		},
		{
			name:     "old_version",
			version:  "7.17.16",
			expected: "cpe:2.3:a:elastic:elasticsearch:7.17.16:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildElasticsearchCPE(tt.version)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// Mock HTTP response builders for testing

// buildMockElasticsearchResponse creates a mock HTTP response from Elasticsearch
func buildMockElasticsearchResponse(version string) []byte {
	jsonBody := `{
  "name" : "test-node",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "abc123",
  "version" : {
    "number" : "` + version + `",
    "build_flavor" : "default",
    "build_type" : "docker",
    "build_hash" : "abc123",
    "build_date" : "2023-11-04T10:04:57.184859352Z",
    "build_snapshot" : false,
    "lucene_version" : "9.8.0",
    "minimum_wire_compatibility_version" : "7.17.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "You Know, for Search"
}`

	httpResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json; charset=UTF-8\r\n" +
		"Content-Length: " + string(rune(len(jsonBody))) + "\r\n" +
		"\r\n" +
		jsonBody

	return []byte(httpResponse)
}

// buildMockOpenSearchResponse creates a mock HTTP response from OpenSearch
func buildMockOpenSearchResponse(version string) []byte {
	jsonBody := `{
  "name" : "test-node",
  "cluster_name" : "opensearch",
  "cluster_uuid" : "abc123",
  "version" : {
    "distribution" : "opensearch",
    "number" : "` + version + `",
    "build_type" : "docker",
    "build_hash" : "abc123",
    "build_date" : "2023-11-04T10:04:57.184859352Z",
    "build_snapshot" : false,
    "lucene_version" : "9.7.0",
    "minimum_wire_compatibility_version" : "7.10.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "The OpenSearch Project: https://opensearch.org/"
}`

	httpResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json; charset=UTF-8\r\n" +
		"Content-Length: " + string(rune(len(jsonBody))) + "\r\n" +
		"\r\n" +
		jsonBody

	return []byte(httpResponse)
}

// buildMock404Response creates a mock HTTP 404 response
func buildMock404Response() []byte {
	httpResponse := "HTTP/1.1 404 Not Found\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<html><body><h1>404 Not Found</h1></body></html>"

	return []byte(httpResponse)
}

// buildMockInvalidJSONResponse creates a mock response with invalid JSON
func buildMockInvalidJSONResponse() []byte {
	httpResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		"{invalid json}"

	return []byte(httpResponse)
}

// buildMockMissingTaglineResponse creates a mock response without tagline
func buildMockMissingTaglineResponse() []byte {
	jsonBody := `{
  "name" : "test-node",
  "cluster_name" : "elasticsearch",
  "version" : {
    "number" : "8.11.3"
  }
}`

	httpResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		jsonBody

	return []byte(httpResponse)
}

// Note: Full integration tests with net.Conn mocking would go here
// For now, we've tested the core logic functions (cleanVersionString, buildElasticsearchCPE)
// and provided mock response builders for future integration test expansion.
