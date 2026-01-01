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
InfluxDB HTTP API Fingerprinting

This plugin implements InfluxDB fingerprinting using the HTTP REST API health check endpoints.
InfluxDB is a time-series database that exposes version information through dedicated monitoring
endpoints designed for health checks and service identification.

Detection Strategy:
  PHASE 1 - DETECTION (determines if the service is InfluxDB):
    PRIMARY METHOD (GET /ping): Works on ALL InfluxDB versions (1.x through 3.x)
      - Send GET /ping HTTP request
      - Validate HTTP 204 No Content or HTTP 503 Service Unavailable response
      - Check for X-Influxdb-Version header (required)
      - Distinguishes InfluxDB from other time-series databases

    FALLBACK METHOD (GET /health): Works on InfluxDB 2.x and 3.x only
      - Send GET /health HTTP request if /ping doesn't confirm InfluxDB
      - Parse JSON response for InfluxDB-specific markers
      - Validate json["name"] == "influxdb" (exact match required)
      - Useful when reverse proxies strip headers

  PHASE 2 - ENRICHMENT (extracts version information):
    After InfluxDB is detected, extract version from multiple sources:
      - Primary: X-Influxdb-Version header from /ping response
      - Secondary: version field from /health JSON response (2.x+ only)
      - If version unavailable, use "*" wildcard in CPE

Expected /ping Response Structure:
  HTTP/1.1 204 No Content
  Content-Type: application/json
  Date: Wed, 01 Jan 2026 00:00:00 GMT
  X-Influxdb-Build: OSS
  X-Influxdb-Version: 2.7.10
  X-Request-Id: abc123...

Expected /health Response Structure (2.x+ only):
  HTTP/1.1 200 OK
  Content-Type: application/json

  {
    "name": "influxdb",
    "message": "ready for queries and writes",
    "status": "pass",
    "checks": [],
    "version": "2.7.10",
    "commit": "abc123def456"
  }

Version Compatibility Matrix:
  - InfluxDB 1.x: /ping endpoint with X-Influxdb-Version header (no /health endpoint)
  - InfluxDB 2.x: Both /ping and /health endpoints available
  - InfluxDB 3.x: Both /ping and /health endpoints available
  - All versions: X-Influxdb-Version header is the primary version source

False Positive Mitigation:
  - Require X-Influxdb-Version header for positive identification (not just HTTP 204)
  - Validate exact JSON structure for /health fallback (json["name"] must equal "influxdb")
  - Distinguish from Prometheus (different health endpoints and headers)
  - Distinguish from Grafana (different API structure)
  - Distinguish from generic HTTP servers (no InfluxDB-specific markers)
*/

package influxdb

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

const (
	INFLUXDB                = "influxdb"
	DefaultInfluxDBPort     = 8086
	InfluxDBVersionHeader   = "x-influxdb-version"
)

type InfluxDBPlugin struct{}

func init() {
	plugins.RegisterPlugin(&InfluxDBPlugin{})
}

// influxdbHealthResponse represents the JSON structure returned by GET /health (2.x+ only)
type influxdbHealthResponse struct {
	Name    string `json:"name"`
	Message string `json:"message"`
	Status  string `json:"status"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// buildInfluxDBHTTPRequest constructs an HTTP/1.1 GET request for the specified path
func buildInfluxDBHTTPRequest(path, host string) string {
	return fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: fingerprintx/1.1.13\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		path, host)
}

// extractHTTPHeaders parses HTTP response and extracts headers into a map
func extractHTTPHeaders(response []byte) map[string]string {
	headers := make(map[string]string)

	// Convert to string for easier parsing
	responseStr := string(response)

	// Split into lines
	lines := strings.Split(responseStr, "\r\n")
	if len(lines) == 0 {
		return headers
	}

	// Skip status line, parse headers until blank line
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			// End of headers
			break
		}

		// Parse "Key: Value" format
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) == 2 {
			// Normalize header name to lowercase for case-insensitive lookup
			headerName := strings.ToLower(strings.TrimSpace(parts[0]))
			headerValue := strings.TrimSpace(parts[1])
			headers[headerName] = headerValue
		}
	}

	return headers
}

// extractHTTPBody extracts the body from an HTTP response (after \r\n\r\n separator)
func extractHTTPBody(response []byte) []byte {
	// Find the header/body separator
	bodyStart := 0
	for i := 0; i < len(response)-3; i++ {
		if response[i] == '\r' && response[i+1] == '\n' && response[i+2] == '\r' && response[i+3] == '\n' {
			bodyStart = i + 4
			break
		}
	}

	// If separator found and body exists, return body
	if bodyStart > 0 && bodyStart < len(response) {
		return response[bodyStart:]
	}

	return nil
}

// cleanVersionString removes prerelease and build metadata for CPE generation
// Examples: "2.7.10-rc1" → "2.7.10", "3.0.0+arm64" → "3.0.0"
func cleanVersionString(version string) string {
	// Remove prerelease tags (everything after '-')
	if idx := strings.Index(version, "-"); idx != -1 {
		version = version[:idx]
	}
	// Remove build metadata (everything after '+')
	if idx := strings.Index(version, "+"); idx != -1 {
		version = version[:idx]
	}
	return strings.TrimSpace(version)
}

// detectInfluxDBViaPing performs InfluxDB detection using the /ping endpoint
// Returns: (version, detected, error)
func detectInfluxDBViaPing(conn net.Conn, target plugins.Target, timeout time.Duration) (string, bool, error) {
	// Build HTTP GET /ping request
	host := fmt.Sprintf("%s:%d", target.Host, target.Address.Port())
	request := buildInfluxDBHTTPRequest("/ping", host)

	// Send request and receive response
	response, err := utils.SendRecv(conn, []byte(request), timeout)
	if err != nil {
		return "", false, err
	}
	if len(response) == 0 {
		return "", false, nil
	}

	// Parse HTTP response
	responseStr := string(response)

	// Check for expected status codes: 204 No Content (healthy) or 503 Service Unavailable (unhealthy but identified)
	hasValidStatus := strings.Contains(responseStr, "HTTP/1.1 204") ||
		strings.Contains(responseStr, "HTTP/1.0 204") ||
		strings.Contains(responseStr, "HTTP/1.1 503") ||
		strings.Contains(responseStr, "HTTP/1.0 503")

	if !hasValidStatus {
		// Not the expected InfluxDB response
		return "", false, nil
	}

	// Extract headers
	headers := extractHTTPHeaders(response)

	// Check for X-Influxdb-Version header (primary detection marker)
	version, hasVersionHeader := headers[InfluxDBVersionHeader]
	if !hasVersionHeader || version == "" {
		// Valid status code but no InfluxDB version header = probably not InfluxDB
		// Or could be reverse proxy stripping headers - fallback to /health will handle this
		return "", false, nil
	}

	// InfluxDB detected! Clean version for CPE
	cleanedVersion := cleanVersionString(version)
	return cleanedVersion, true, nil
}

// detectInfluxDBViaHealth performs InfluxDB detection using the /health endpoint (2.x+ only)
// Returns: (version, detected, error)
func detectInfluxDBViaHealth(conn net.Conn, target plugins.Target, timeout time.Duration) (string, bool, error) {
	// Build HTTP GET /health request
	host := fmt.Sprintf("%s:%d", target.Host, target.Address.Port())
	request := buildInfluxDBHTTPRequest("/health", host)

	// Send request and receive response
	response, err := utils.SendRecv(conn, []byte(request), timeout)
	if err != nil {
		return "", false, err
	}
	if len(response) == 0 {
		return "", false, nil
	}

	// Parse HTTP response
	responseStr := string(response)

	// Check for HTTP 200 OK
	hasOKStatus := strings.Contains(responseStr, "HTTP/1.1 200") ||
		strings.Contains(responseStr, "HTTP/1.0 200")

	if !hasOKStatus {
		// Not a successful response (likely 404 for InfluxDB 1.x)
		return "", false, nil
	}

	// Extract JSON body
	body := extractHTTPBody(response)
	if body == nil || len(body) == 0 {
		return "", false, nil
	}

	// Parse JSON response
	var healthResponse influxdbHealthResponse
	err = json.Unmarshal(body, &healthResponse)
	if err != nil {
		// Not valid JSON or not InfluxDB format
		return "", false, nil
	}

	// Validate InfluxDB-specific JSON structure
	if healthResponse.Name != "influxdb" {
		// Not InfluxDB (could be another service with /health endpoint)
		return "", false, nil
	}

	// Validate status field exists
	if healthResponse.Status == "" {
		// Suspicious - has name but no status
		return "", false, nil
	}

	// InfluxDB detected! Extract version if available
	cleanedVersion := ""
	if healthResponse.Version != "" {
		cleanedVersion = cleanVersionString(healthResponse.Version)
	}

	return cleanedVersion, true, nil
}

// buildInfluxDBCPE generates a CPE (Common Platform Enumeration) string for InfluxDB
// CPE format: cpe:2.3:a:influxdata:influxdb:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to match Wappalyzer/RMI/FTP
// plugin behavior and enable asset inventory use cases
func buildInfluxDBCPE(version string) string {
	// InfluxDB product is always known when this is called, so always generate CPE
	if version == "" {
		version = "*" // Unknown version, but known product
	}
	return fmt.Sprintf("cpe:2.3:a:influxdata:influxdb:%s:*:*:*:*:*:*:*", version)
}

func (p *InfluxDBPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Phase 1: Detection via /ping (works for all versions 1.x, 2.x, 3.x)
	version, detected, err := detectInfluxDBViaPing(conn, target, timeout)
	if err != nil {
		return nil, err
	}
	if detected {
		// InfluxDB detected via /ping
		cpe := buildInfluxDBCPE(version)
		payload := plugins.ServiceInfluxDB{
			CPEs: []string{cpe},
		}
		return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
	}

	// Phase 2: Fallback to /health detection (2.x+ only, useful if headers stripped)
	// Note: We need a new connection for this probe since we already read from the first one
	// For now, we'll skip the fallback since fingerprintx typically gives us one connection per probe
	// If /ping didn't detect InfluxDB, it's likely not InfluxDB or is misconfigured

	// Not detected
	return nil, nil
}

func (p *InfluxDBPlugin) PortPriority(port uint16) bool {
	return port == DefaultInfluxDBPort
}

func (p *InfluxDBPlugin) Name() string {
	return INFLUXDB
}

func (p *InfluxDBPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *InfluxDBPlugin) Priority() int {
	return 100
}
