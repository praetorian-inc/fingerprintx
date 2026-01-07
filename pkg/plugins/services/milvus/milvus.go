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

package milvus

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

/*
Milvus Vector Database Fingerprinting

This plugin implements Milvus fingerprinting for the database service on port 19530.
Milvus is a vector database that uses gRPC as its primary communication protocol,
with HTTP REST API support in v2.3.x+.

**SIGNIFICANCE:** This is the FIRST gRPC-based fingerprinting plugin in fingerprintx.
All previous plugins used HTTP, binary protocols (MongoDB), or text protocols.
This establishes reusable patterns for future gRPC service fingerprinting.

Detection Strategy:
  PHASE 1 - DETECTION (determines if the service is Milvus):
    PRIMARY PATH: Try GetVersion RPC call directly
      - Call milvus.proto.milvus.MilvusService/GetVersion
      - This works without gRPC reflection
      - If response contains valid version → Milvus detected

    SECONDARY PATH: HTTP REST API (v2.3.x+) on same port
      - GET http://host:19530/v2/vector/collections (Milvus v2 API)
      - Or GET http://host:19530/api/v1/health (health check endpoint)
      - If response indicates Milvus API → Milvus detected

  PHASE 2 - ENRICHMENT:
    After Milvus is detected, version is already extracted from GetVersion
    or parsed from HTTP API response. No additional enrichment needed.

Protocol Details:

  gRPC GetVersion RPC:
    Method: /milvus.proto.milvus.MilvusService/GetVersion
    Request: Empty message (for simplicity, we'll use empty byte slice)
    Response: Contains "version" field with semantic version string

    NOTE: We use direct RPC invocation rather than importing full milvus-proto
    definitions to avoid heavyweight dependencies. The GetVersion response is
    simple enough that we can parse the version string from the raw response.

  HTTP REST API:
    Port: 19530 (same as gRPC)
    Endpoints:
      - GET /v2/vector/collections (Milvus v2 API)
      - GET /api/v1/health (health check)
    Response: JSON with Milvus-specific structure

Default Port:
  - 19530: gRPC API + HTTP REST API

Version Compatibility:
  - Milvus 2.3.x+: Full support (GetVersion + HTTP REST API)
  - Milvus 2.0-2.2: gRPC GetVersion only
  - Milvus 1.x: May not support GetVersion

CPE Format:
  - cpe:2.3:a:milvus:milvus:{version}:*:*:*:*:*:*:*
  - Uses "*" for unknown version if detection succeeds but version extraction fails

NOTE: For Prometheus metrics endpoint (port 9091), see milvus_metrics.go
*/

type MilvusPlugin struct{}

const MILVUS = "milvus"

// milvusMetadata holds enriched metadata extracted from Milvus responses
type milvusMetadata struct {
	Version string // Milvus version string (e.g., "2.6.7")
}

func init() {
	plugins.RegisterPlugin(&MilvusPlugin{})
}

// tryGetVersionViaGRPC attempts to retrieve Milvus version using gRPC GetVersion RPC.
//
// This function calls the GetVersion RPC directly without using gRPC reflection.
// The response is parsed to extract the version string.
//
// Parameters:
//   - target: Network address (e.g., "localhost:19530")
//   - timeout: RPC timeout duration
//
// Returns:
//   - string: Version string if successful, empty string otherwise
//   - bool: true if Milvus detected (even if version extraction fails)
//   - error: Error details if detection failed
func tryGetVersionViaGRPC(target string, timeout time.Duration) (string, bool, error) {
	// Establish gRPC connection
	conn, err := utils.GRPCDialWithTimeout(target, timeout)
	if err != nil {
		return "", false, err
	}
	defer conn.Close()

	// Call GetVersion RPC
	// Method: /milvus.proto.milvus.MilvusService/GetVersion
	// Request: Empty (protobuf empty message is just a zero-length byte slice)
	method := "/milvus.proto.milvus.MilvusService/GetVersion"
	request := []byte{} // Empty request

	response, err := utils.GRPCInvokeUnary(conn, method, request, timeout)
	if err != nil {
		// gRPC call failed - not Milvus or network error
		return "", false, err
	}

	// Response received - this is likely Milvus
	// Parse version from response
	// The response is a protobuf message with a "version" string field
	// For simplicity, we'll use string search rather than full protobuf parsing
	version := parseVersionFromProtobuf(response)

	return version, true, nil
}

// parseVersionFromProtobuf extracts version string from a protobuf message.
//
// This is a simplified parser that looks for the version string pattern in the
// raw protobuf bytes. It's less robust than full protobuf parsing but sufficient
// for fingerprinting without importing heavy proto dependencies.
//
// Protobuf string encoding: field_number(varint) + length(varint) + string_bytes
// For GetVersionResponse, version is typically field 2 (wire type 2 = length-delimited)
//
// Parameters:
//   - data: Raw protobuf response bytes
//
// Returns:
//   - string: Extracted version string, or empty if not found
func parseVersionFromProtobuf(data []byte) string {
	// Look for semantic version pattern: X.Y.Z or vX.Y.Z
	// This regex matches common version formats in Milvus responses
	versionRegex := regexp.MustCompile(`v?([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.]+)?)`)

	// Convert to string for regex matching (protobuf strings are UTF-8)
	dataStr := string(data)
	matches := versionRegex.FindStringSubmatch(dataStr)
	if len(matches) >= 2 {
		// Remove "v" prefix if present (normalize to "2.6.7" format)
		version := matches[1]
		return strings.TrimPrefix(version, "v")
	}

	return ""
}

// tryGetVersionViaHTTPREST attempts to detect Milvus using HTTP REST API on same port.
//
// Milvus v2.3.x+ supports HTTP REST API on the same port as gRPC (19530).
// This is a secondary detection method when gRPC fails or is unavailable.
//
// IMPORTANT: This function reuses the provided connection via custom HTTP transport
// to avoid creating new connections, following the same pattern as MilvusMetricsPlugin.
//
// Parameters:
//   - conn: Existing network connection to reuse
//   - target: Target information (host for Host header)
//   - timeout: HTTP request timeout duration
//
// Returns:
//   - string: Version string if successful, empty string otherwise
//   - bool: true if Milvus detected via HTTP REST API
//   - error: Error details if detection failed
func tryGetVersionViaHTTPREST(conn net.Conn, target plugins.Target, timeout time.Duration) (string, bool, error) {
	// Build URL using remote address from connection (gives "IP:port")
	// Use the most reliable Milvus API endpoint: /v1/vector/collections
	// This endpoint is widely supported and returns a clear Milvus-specific response
	url := fmt.Sprintf("http://%s/v1/vector/collections", conn.RemoteAddr().String())

	// Create HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", false, err
	}

	// Set Host header if target specifies one
	if target.Host != "" {
		req.Host = target.Host
	}

	// Set User-Agent header (some servers require this)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")

	// Create HTTP client with custom dialer to reuse the provided connection
	// IMPORTANT: We only make ONE request per connection to avoid connection reuse issues
	// After an HTTP request completes, the connection may be closed, making it unusable
	// for subsequent requests.
	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, err
	}

	bodyStr := string(body)

	// Check for Milvus-specific response patterns
	// Pattern 1: Explicit "milvus" or "Milvus" in response body
	// Pattern 2: Milvus v1/v2 API JSON response with "code" and "data" fields
	//   Example: {"code":200,"data":["collection1"]}
	// Pattern 3: Server header contains "milvus"
	isMilvusResponse := false

	// Direct Milvus reference in body or headers
	if strings.Contains(bodyStr, "milvus") ||
		strings.Contains(bodyStr, "Milvus") ||
		strings.Contains(strings.ToLower(resp.Header.Get("Server")), "milvus") {
		isMilvusResponse = true
	}

	// Milvus v1/v2 API JSON structure: {"code":200,"data":...}
	// This is the standard Milvus REST API response format
	if resp.StatusCode == http.StatusOK &&
		strings.Contains(resp.Header.Get("Content-Type"), "application/json") &&
		(strings.Contains(bodyStr, `"code":`) && strings.Contains(bodyStr, `"data":`)) {
		isMilvusResponse = true
	}

	if !isMilvusResponse {
		return "", false, nil
	}

	// Detected Milvus, try to extract version
	// Version may be in response headers or body
	version := extractVersionFromHTTPResponse(bodyStr, resp.Header)
	return version, true, nil
}

// extractVersionFromHTTPResponse attempts to extract version from HTTP response.
//
// Looks for version patterns in response body or headers.
//
// Parameters:
//   - body: HTTP response body as string
//   - headers: HTTP response headers
//
// Returns:
//   - string: Extracted version string, or empty if not found
func extractVersionFromHTTPResponse(body string, headers http.Header) string {
	// Try to find version in response body (JSON format)
	// Pattern: "version":"2.6.7" or "version": "v2.6.7"
	versionRegex := regexp.MustCompile(`"version"\s*:\s*"v?([0-9]+\.[0-9]+\.[0-9]+[^"]*)"`)
	matches := versionRegex.FindStringSubmatch(body)
	if len(matches) >= 2 {
		return strings.TrimPrefix(matches[1], "v")
	}

	// Try to find version in headers (Server header or custom header)
	if serverHeader := headers.Get("Server"); serverHeader != "" {
		versionRegex := regexp.MustCompile(`v?([0-9]+\.[0-9]+\.[0-9]+)`)
		matches := versionRegex.FindStringSubmatch(serverHeader)
		if len(matches) >= 2 {
			return strings.TrimPrefix(matches[1], "v")
		}
	}

	return ""
}

// DetectMilvus performs Milvus fingerprinting using gRPC and HTTP REST API.
//
// Detection Strategy:
//  1. PRIMARY: Try gRPC GetVersion RPC on target port (19530)
//  2. SECONDARY: Try HTTP REST API on same port (Milvus v2.3.x+ feature)
//     Uses provided connection to avoid creating new connections
//
// Parameters:
//   - conn: Network connection (reused for HTTP REST API detection)
//   - timeout: Detection timeout duration
//   - target: Target information
//
// Returns:
//   - milvusMetadata: Extracted metadata (version)
//   - bool: true if Milvus detected
//   - error: Error details if detection failed
func DetectMilvus(conn net.Conn, timeout time.Duration, target plugins.Target) (milvusMetadata, bool, error) {
	metadata := milvusMetadata{}

	// Extract host and port from target
	host := target.Host
	targetAddr := fmt.Sprintf("%s:%d", host, target.Address.Port())

	// PHASE 1: Try HTTP REST API first (Milvus v2.3.x+ feature)
	// This is now the primary detection method as it reuses the provided connection
	version, detected, err := tryGetVersionViaHTTPREST(conn, target, timeout)
	if detected {
		metadata.Version = version
		return metadata, true, nil
	}

	// PHASE 2: Try gRPC GetVersion on target port (fallback detection)
	version, detected, err = tryGetVersionViaGRPC(targetAddr, timeout)
	if detected {
		metadata.Version = version
		return metadata, true, nil
	}

	// Both detection methods failed
	return metadata, false, err
}

// buildMilvusCPE constructs a CPE (Common Platform Enumeration) string for Milvus.
// CPE format: cpe:2.3:a:milvus:milvus:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to match other plugins'
// behavior and enable asset inventory use cases.
//
// Parameters:
//   - version: Milvus version string (e.g., "2.6.7"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" for unknown version
func buildMilvusCPE(version string) string {
	// Milvus product is always known when this is called, so always generate CPE
	if version == "" {
		version = "*" // Unknown version, but known product
	}
	return fmt.Sprintf("cpe:2.3:a:milvus:milvus:%s:*:*:*:*:*:*:*", version)
}

func (p *MilvusPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	metadata, detected, err := DetectMilvus(conn, timeout, target)
	if !detected {
		return nil, err
	}

	// Milvus detected - create service payload
	payload := plugins.ServiceMilvus{}

	// Always generate CPE - uses "*" for unknown version
	cpe := buildMilvusCPE(metadata.Version)
	payload.CPEs = []string{cpe}

	return plugins.CreateServiceFrom(target, payload, false, metadata.Version, plugins.TCP), nil
}

func (p *MilvusPlugin) PortPriority(port uint16) bool {
	return port == 19530
}

func (p *MilvusPlugin) Name() string {
	return MILVUS
}

func (p *MilvusPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *MilvusPlugin) Priority() int {
	return 50 // Run before generic HTTP (100)
}
