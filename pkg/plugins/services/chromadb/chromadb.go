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

/*
ChromaDB HTTP API Fingerprinting

This plugin implements ChromaDB fingerprinting using HTTP REST API detection.
ChromaDB is an open-source vector database for AI applications that exposes version
information and unique service identification through well-known HTTP endpoints.

Detection Strategy:
  PHASE 1 - DETECTION (determines if the service is ChromaDB):
    PRIMARY METHOD (GET /api/v1/heartbeat): Works on ALL ChromaDB versions
      - Send GET /api/v1/heartbeat HTTP request
      - Parse JSON response for characteristic ChromaDB marker
      - Validate json["nanosecond heartbeat"] field exists (unique to ChromaDB)
      - Validate value is numeric nanosecond timestamp (> 1e18)
      - If all checks pass → ChromaDB detected

  PHASE 2 - ENRICHMENT (attempts to retrieve version information):
    After ChromaDB is detected, extract version from /api/v1/version endpoint:
      - Primary: GET /api/v1/version → json["version"] field
      - Version format: Semantic versioning (e.g., "1.4.0", "0.5.20")
      - If version unavailable, use "*" wildcard in CPE

ChromaDB Heartbeat Endpoint Response Structure:

 Example ChromaDB 1.x Response:
   HTTP/1.1 200 OK
   Content-Type: application/json
   Server: uvicorn

   {"nanosecond heartbeat": 1735740123456789000}

 Example ChromaDB 0.x Response (same structure):
   {"nanosecond heartbeat": 1704067200000000000}

ChromaDB Version Endpoint Response Structure:

 Example Version Response:
   HTTP/1.1 200 OK
   Content-Type: application/json
   Server: uvicorn

   {"version": "1.4.0"}

Version Compatibility Matrix:
  - ChromaDB 1.x: Heartbeat and version endpoints present, stable API
  - ChromaDB 0.6.x: Heartbeat and version endpoints present
  - ChromaDB 0.5.x: Heartbeat and version endpoints present
  - All versions: Field name "nanosecond heartbeat" (with space) is unique marker
  - All versions: Returns nanosecond-precision Unix timestamp

False Positive Mitigation:
  - Require exact match: json["nanosecond heartbeat"] field (unusual field name with space)
  - Validate value is numeric and > 1e18 (reasonable nanosecond timestamp)
  - Reject responses missing required JSON structure
  - Distinguish from generic HTTP servers and other vector databases (Milvus, Weaviate, Qdrant)
*/

package chromadb

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

const CHROMADB = "chromadb"
const CHROMADBTLS = "chromadb"
const DefaultChromaDBPort = 8000

type ChromaDBPlugin struct{}
type ChromaDBTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&ChromaDBPlugin{})
	plugins.RegisterPlugin(&ChromaDBTLSPlugin{})
}

// chromadbHeartbeatResponse represents the JSON structure returned by GET /api/v1/heartbeat
type chromadbHeartbeatResponse struct {
	NanosecondHeartbeat int64 `json:"nanosecond heartbeat"`
}

// chromadbVersionResponse represents the JSON structure returned by GET /api/v1/version
type chromadbVersionResponse struct {
	Version string `json:"version"`
}

// parseChromaDBHeartbeat validates a ChromaDB heartbeat response and checks for unique marker.
//
// Validation rules:
//   - json["nanosecond heartbeat"] must exist (field name with space is unique to ChromaDB)
//   - Value must be numeric and > 1e18 (reasonable nanosecond timestamp)
//
// Parameters:
//   - response: Raw HTTP response body (expected to be JSON)
//
// Returns:
//   - bool: true if ChromaDB detected, false otherwise
//   - int64: Heartbeat value (0 if detection failed)
func parseChromaDBHeartbeat(response []byte) (bool, int64) {
	// Empty response check
	if len(response) == 0 {
		return false, 0
	}

	// Parse JSON
	var parsed chromadbHeartbeatResponse
	if err := json.Unmarshal(response, &parsed); err != nil {
		return false, 0
	}

	// Validate nanosecond heartbeat field exists and is reasonable
	// ChromaDB returns Unix nanosecond timestamps (> 1e18)
	const minNanosecondTimestamp = 1_000_000_000_000_000_000 // 1e18
	if parsed.NanosecondHeartbeat < minNanosecondTimestamp {
		return false, 0
	}

	// ChromaDB detected! Return heartbeat value
	return true, parsed.NanosecondHeartbeat
}

// getChromaDBVersion attempts to extract version from /api/v1/version endpoint.
//
// This is an enrichment step that happens after detection succeeds. Version extraction
// may fail if the endpoint is unavailable, authentication is required, or response is malformed.
//
// Parameters:
//   - conn: Network connection to the target service
//   - target: Target information for service creation
//   - timeout: Timeout duration for network operations
//
// Returns:
//   - string: Version string (empty if unavailable)
//   - error: Error details if version extraction failed (non-fatal)
func getChromaDBVersion(conn net.Conn, target plugins.Target, timeout time.Duration) (string, error) {
	// Build host string for HTTP Host header
	host := fmt.Sprintf("%s:%d", target.Host, target.Address.Port())

	// Build HTTP GET /api/v1/version request
	request := buildChromaDBHTTPRequest("/api/v1/version", host)

	// Send request and receive response
	response, err := utils.SendRecv(conn, []byte(request), timeout)
	if err != nil {
		return "", err
	}

	if len(response) == 0 {
		return "", nil
	}

	// Extract JSON body from HTTP response
	jsonBody := extractHTTPBody(response)
	if len(jsonBody) == 0 {
		return "", nil
	}

	// Parse JSON response
	var versionResp chromadbVersionResponse
	if err := json.Unmarshal(jsonBody, &versionResp); err != nil {
		return "", nil // Parse failure = no version (non-fatal)
	}

	// Clean version string (remove pre-release tags, commit hashes)
	version := cleanChromaDBVersion(versionResp.Version)

	return version, nil
}

// cleanChromaDBVersion removes pre-release suffixes and commit hashes from version strings.
//
// Examples:
//   - "1.4.0-alpha" → "1.4.0"
//   - "1.4.0+abc123" → "1.4.0"
//   - "1.4.0-beta.1" → "1.4.0"
//
// Parameters:
//   - version: Raw version string from API
//
// Returns:
//   - string: Cleaned semantic version (empty if invalid)
func cleanChromaDBVersion(version string) string {
	if version == "" {
		return ""
	}

	// Remove pre-release tags: "1.4.0-alpha" → "1.4.0"
	if idx := strings.Index(version, "-"); idx != -1 {
		version = version[:idx]
	}

	// Remove commit hashes: "1.4.0+abc123" → "1.4.0"
	if idx := strings.Index(version, "+"); idx != -1 {
		version = version[:idx]
	}

	return version
}

// buildChromaDBCPE constructs a CPE (Common Platform Enumeration) string for ChromaDB.
// CPE format: cpe:2.3:a:chroma:chromadb:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to match Wappalyzer/RMI/FTP
// plugin behavior and enable asset inventory use cases.
//
// Parameters:
//   - version: ChromaDB version string (e.g., "1.4.0"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" for unknown version
func buildChromaDBCPE(version string) string {
	// ChromaDB product is always known when this is called, so always generate CPE
	if version == "" {
		version = "*" // Unknown version, but known product (matches RMI/FTP/Wappalyzer pattern)
	}
	return fmt.Sprintf("cpe:2.3:a:chroma:chromadb:%s:*:*:*:*:*:*:*", version)
}

// buildChromaDBHTTPRequest constructs an HTTP/1.1 GET request for the specified path.
//
// Parameters:
//   - path: HTTP path (e.g., "/api/v1/heartbeat", "/api/v1/version")
//   - host: Target host:port (e.g., "localhost:8000")
//
// Returns:
//   - string: Complete HTTP request ready to send
func buildChromaDBHTTPRequest(path, host string) string {
	return fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: fingerprintx/1.1.13\r\n"+
			"Accept: application/json\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		path, host)
}

// extractHTTPBody extracts the JSON body from an HTTP response.
//
// HTTP responses have format: headers\r\n\r\nbody
// This function finds the separator and returns everything after it.
//
// Parameters:
//   - response: Raw HTTP response bytes
//
// Returns:
//   - []byte: JSON body (empty if separator not found)
func extractHTTPBody(response []byte) []byte {
	// Look for "\r\n\r\n" which separates headers from body
	for i := 0; i < len(response)-3; i++ {
		if response[i] == '\r' && response[i+1] == '\n' && response[i+2] == '\r' && response[i+3] == '\n' {
			bodyStart := i + 4
			if bodyStart < len(response) {
				return response[bodyStart:]
			}
			break
		}
	}

	// No HTTP headers found, treat entire response as JSON (edge case)
	return response
}

// detectChromaDB performs ChromaDB detection using HTTP REST API.
//
// Detection phases:
//  1. Send HTTP GET /api/v1/heartbeat request (DETECTION)
//  2. Receive and parse JSON response
//  3. Validate ChromaDB markers (json["nanosecond heartbeat"] exists and valid)
//  4. Extract version from GET /api/v1/version endpoint (ENRICHMENT)
//
// Parameters:
//   - conn: Network connection to the target service
//   - target: Target information for service creation
//   - timeout: Timeout duration for network operations
//   - tls: Whether the connection uses TLS
//
// Returns:
//   - *plugins.Service: Service information if ChromaDB detected, nil otherwise
//   - error: Error details if detection failed
func detectChromaDB(conn net.Conn, target plugins.Target, timeout time.Duration, tls bool) (*plugins.Service, error) {
	// Build host string for HTTP Host header
	host := fmt.Sprintf("%s:%d", target.Host, target.Address.Port())

	// Build HTTP GET /api/v1/heartbeat request (DETECTION PHASE)
	request := buildChromaDBHTTPRequest("/api/v1/heartbeat", host)

	// Send request and receive response
	response, err := utils.SendRecv(conn, []byte(request), timeout)
	if err != nil {
		return nil, err
	}

	// Empty response check
	if len(response) == 0 {
		return nil, nil
	}

	// Extract JSON body from HTTP response
	jsonBody := extractHTTPBody(response)

	// Parse ChromaDB heartbeat response
	detected, _ := parseChromaDBHeartbeat(jsonBody)
	if !detected {
		return nil, nil
	}

	// ENRICHMENT PHASE: Extract version from /api/v1/version
	// Note: We ignore errors here because version extraction is optional
	version, _ := getChromaDBVersion(conn, target, timeout)

	// Build service metadata
	cpe := buildChromaDBCPE(version)
	payload := plugins.ServiceChromaDB{
		CPEs: []string{cpe},
	}

	if tls {
		return plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS), nil
	}
	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *ChromaDBPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectChromaDB(conn, target, timeout, false)
}

func (p *ChromaDBPlugin) PortPriority(port uint16) bool {
	return port == DefaultChromaDBPort
}

func (p *ChromaDBPlugin) Name() string {
	return CHROMADB
}

func (p *ChromaDBPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *ChromaDBPlugin) Priority() int {
	return 50 // Run before generic HTTP (100), after highly specific protocols
}

func (p *ChromaDBTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectChromaDB(conn, target, timeout, true)
}

func (p *ChromaDBTLSPlugin) PortPriority(port uint16) bool {
	return port == DefaultChromaDBPort
}

func (p *ChromaDBTLSPlugin) Name() string {
	return CHROMADBTLS
}

func (p *ChromaDBTLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *ChromaDBTLSPlugin) Priority() int {
	return 51 // Just after non-TLS ChromaDB
}
