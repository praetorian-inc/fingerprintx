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
CouchDB HTTP API Fingerprinting

This plugin implements CouchDB fingerprinting using HTTP REST API detection.
CouchDB exposes version information and service identification through well-known
HTTP endpoints that require no authentication.

Detection Strategy:
  PHASE 1 - DETECTION (determines if the service is CouchDB):
    PRIMARY METHOD (GET /): Works on ALL CouchDB versions (1.x through 3.x)
      - Send GET / HTTP request to root endpoint
      - Parse JSON response for characteristic CouchDB markers
      - Validate json["couchdb"] == "Welcome" (exact match required)
      - Validate json["vendor"]["name"] field exists
      - If all checks pass → CouchDB detected

  PHASE 2 - ENRICHMENT (attempts to retrieve version information):
    After CouchDB is detected, extract version from JSON response:
      - Primary: json["version"] field (e.g., "3.4.2", "2.3.1", "1.6.1")
      - Fallback: Parse Server header if version field missing
      - If version unavailable, use "*" wildcard in CPE

CouchDB Root Endpoint Response Structure:

 Example CouchDB 3.x Response:
   HTTP/1.1 200 OK
   Content-Type: application/json
   Server: CouchDB/3.4.2 (Erlang OTP/25)

   {
     "couchdb": "Welcome",
     "version": "3.4.2",
     "git_sha": "6e5ad2a5c",
     "uuid": "9ddf59457dbb8772316cf06fc5e5a2e4",
     "features": ["access-ready", "partitioned", ...],
     "vendor": {"name": "The Apache Software Foundation"}
   }

 Example CouchDB 2.x Response:
   {
     "couchdb": "Welcome",
     "version": "2.3.1",
     "git_sha": "c298091a4",
     "uuid": "85fb71bf700c17267fef77535820e371",
     "features": ["scheduler"],
     "vendor": {"name": "The Apache Software Foundation"}
   }

 Example CouchDB 1.x Response:
   {
     "couchdb": "Welcome",
     "version": "1.6.1",
     "uuid": "85fb71bf700c17267fef77535820e371",
     "vendor": {"name": "The Apache Software Foundation"}
   }

Version Compatibility Matrix:
  - CouchDB 1.x: Root endpoint returns version, no features array
  - CouchDB 2.x: Root endpoint includes features array, clustering support
  - CouchDB 3.x: Root endpoint with enhanced features, stable API
  - All versions: json["couchdb"] == "Welcome" is constant
  - All versions: json["version"] field always present (when not hidden by admin config)

False Positive Mitigation:
  - Require exact match: json["couchdb"] == "Welcome" (case-sensitive)
  - Validate vendor field exists
  - Reject responses missing required JSON structure
  - Distinguish from generic HTTP servers and other NoSQL databases
*/

package couchdb

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

const COUCHDB = "couchdb"
const COUCHDBTLS = "couchdb"

type COUCHDBPlugin struct{}
type COUCHDBTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&COUCHDBPlugin{})
	plugins.RegisterPlugin(&COUCHDBTLSPlugin{})
}

// couchdbRootResponse represents the JSON structure returned by GET /
type couchdbRootResponse struct {
	CouchDB string `json:"couchdb"`
	Version string `json:"version"`
	Vendor  struct {
		Name string `json:"name"`
	} `json:"vendor"`
}

// parseCouchDBResponse validates a CouchDB root endpoint response and extracts version.
//
// Validation rules:
//   - json["couchdb"] must equal "Welcome" (case-sensitive)
//   - json["vendor"] must exist (checking for vendor.name)
//   - Version extracted from json["version"] if present
//
// Parameters:
//   - response: Raw HTTP response body (expected to be JSON)
//
// Returns:
//   - bool: true if CouchDB detected, false otherwise
//   - string: Version string (empty if not found or detection failed)
func parseCouchDBResponse(response []byte) (bool, string) {
	// Empty response check
	if len(response) == 0 {
		return false, ""
	}

	// Parse JSON
	var parsed couchdbRootResponse
	if err := json.Unmarshal(response, &parsed); err != nil {
		return false, ""
	}

	// Validate CouchDB marker (exact match required)
	if parsed.CouchDB != "Welcome" {
		return false, ""
	}

	// Validate vendor field exists (vendor.name should be present)
	// Note: We only check if vendor.name is a string, not its specific value
	// because theoretically someone could fork CouchDB with a different vendor name
	if parsed.Vendor.Name == "" {
		return false, ""
	}

	// CouchDB detected! Extract version (may be empty if configured to hide)
	return true, parsed.Version
}

// buildCouchDBCPE constructs a CPE (Common Platform Enumeration) string for CouchDB.
// CPE format: cpe:2.3:a:apache:couchdb:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to match Wappalyzer/RMI/FTP
// plugin behavior and enable asset inventory use cases.
//
// Parameters:
//   - version: CouchDB version string (e.g., "3.4.2"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" for unknown version
func buildCouchDBCPE(version string) string {
	// CouchDB product is always known when this is called, so always generate CPE
	if version == "" {
		version = "*" // Unknown version, but known product (matches RMI/FTP/Wappalyzer pattern)
	}
	return fmt.Sprintf("cpe:2.3:a:apache:couchdb:%s:*:*:*:*:*:*:*", version)
}

// buildCouchDBHTTPRequest constructs an HTTP/1.1 GET request for the specified path.
//
// Parameters:
//   - path: HTTP path (e.g., "/", "/_session")
//   - host: Target host:port (e.g., "localhost:5984")
//
// Returns:
//   - string: Complete HTTP request ready to send
func buildCouchDBHTTPRequest(path, host string) string {
	return fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: fingerprintx/1.1.13\r\n"+
			"Accept: application/json\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		path, host)
}

// detectCouchDB performs CouchDB detection using HTTP REST API.
//
// Detection phases:
//  1. Send HTTP GET / request
//  2. Receive and parse JSON response
//  3. Validate CouchDB markers (json["couchdb"] == "Welcome")
//  4. Extract version from json["version"] field
//
// Parameters:
//   - conn: Network connection to the target service
//   - target: Target information for service creation
//   - timeout: Timeout duration for network operations
//   - tls: Whether the connection uses TLS
//
// Returns:
//   - *plugins.Service: Service information if CouchDB detected, nil otherwise
//   - error: Error details if detection failed
func detectCouchDB(conn net.Conn, target plugins.Target, timeout time.Duration, tls bool) (*plugins.Service, error) {
	// Build host string for HTTP Host header
	host := fmt.Sprintf("%s:%d", target.Host, target.Address.Port())

	// Build HTTP GET / request
	request := buildCouchDBHTTPRequest("/", host)

	// Send request and receive response
	response, err := utils.SendRecv(conn, []byte(request), timeout)
	if err != nil {
		return nil, err
	}

	// Empty response check
	if len(response) == 0 {
		return nil, nil
	}

	// HTTP responses typically have headers followed by blank line, then body
	// We need to extract just the JSON body part
	// Look for "\r\n\r\n" which separates headers from body
	bodyStart := 0
	for i := 0; i < len(response)-3; i++ {
		if response[i] == '\r' && response[i+1] == '\n' && response[i+2] == '\r' && response[i+3] == '\n' {
			bodyStart = i + 4
			break
		}
	}

	// If we found the body separator, extract JSON body
	var jsonBody []byte
	if bodyStart > 0 && bodyStart < len(response) {
		jsonBody = response[bodyStart:]
	} else {
		// No HTTP headers found, treat entire response as JSON (edge case)
		jsonBody = response
	}

	// Parse CouchDB response
	detected, version := parseCouchDBResponse(jsonBody)
	if !detected {
		return nil, nil
	}

	// Build service metadata
	cpe := buildCouchDBCPE(version)
	payload := plugins.ServiceCouchDB{
		CPEs: []string{cpe},
	}

	if tls {
		return plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS), nil
	}
	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *COUCHDBPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectCouchDB(conn, target, timeout, false)
}

func (p *COUCHDBPlugin) PortPriority(port uint16) bool {
	return port == 5984
}

func (p *COUCHDBPlugin) Name() string {
	return COUCHDB
}

func (p *COUCHDBPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *COUCHDBPlugin) Priority() int {
	return 100
}

func (p *COUCHDBTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectCouchDB(conn, target, timeout, true)
}

func (p *COUCHDBTLSPlugin) PortPriority(port uint16) bool {
	return port == 6984
}

func (p *COUCHDBTLSPlugin) Name() string {
	return COUCHDBTLS
}

func (p *COUCHDBTLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *COUCHDBTLSPlugin) Priority() int {
	return 101
}
