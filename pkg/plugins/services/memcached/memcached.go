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
Package memcached implements fingerprinting for Memcached distributed memory cache servers.

Memcached Wire Protocol Detection

This plugin implements Memcached fingerprinting using the text (ASCII) protocol
to ensure compatibility across all Memcached versions from 1.4.x to 1.6.x+.

Detection Strategy:
  PHASE 1 - DETECTION (determines if the service is Memcached):
    PRIMARY PATH: version command
      - Send: version\r\n
      - Expected: VERSION <version>\r\n
      - Works on ALL Memcached versions (1.0+ to 1.6.x+)
      - Directly provides version string (100% confidence)

    SECONDARY PATH (FALLBACK): stats command
      - Send: stats\r\n
      - Expected: STAT <key> <value>\r\n ... END\r\n
      - Contains "STAT version <version>" line
      - Works on ALL Memcached versions

  PHASE 2 - ENRICHMENT (extracts version information):
    After Memcached is detected, version is already extracted from the detection response.
    No additional enrichment needed (unlike Redis INFO or MongoDB buildInfo).

Memcached Text Protocol:

version Command:
  Request:  version\r\n
  Response: VERSION <version>\r\n

  Example:
    Request:  version\r\n
    Response: VERSION 1.6.22\r\n

stats Command (Fallback):
  Request:  stats\r\n
  Response: STAT <name> <value>\r\n
            STAT <name> <value>\r\n
            ...
            END\r\n

  Example:
    Request:  stats\r\n
    Response: STAT pid 1162\r\n
              STAT uptime 5022\r\n
              STAT version 1.6.22\r\n
              ...
              END\r\n

Error Responses:
  - ERROR\r\n - Unknown command (indicates NOT Memcached)
  - CLIENT_ERROR <error>\r\n - Invalid command format
  - SERVER_ERROR <error>\r\n - Server error

Version Compatibility Matrix:
  - Memcached 1.4.x: Text + Binary protocols, UDP enabled
  - Memcached 1.5.x: Text + Binary protocols, UDP disabled by default, TLS added
  - Memcached 1.6.x: Text + Meta protocols, Binary deprecated, extstore support

Note: The text protocol (including version and stats commands) is supported
across all versions and will be maintained indefinitely per Memcached project.
*/
package memcached

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type MEMCACHEDPlugin struct{}

const MEMCACHED = "memcached"

// Memcached default port
const DEFAULT_PORT = 11211

func init() {
	plugins.RegisterPlugin(&MEMCACHEDPlugin{})
}

// checkMemcachedVersionResponse validates that the response is a valid Memcached
// version command response.
//
// Expected format: "VERSION <version>\r\n"
//
// Parameters:
//   - response: The raw response bytes from the Memcached server
//
// Returns:
//   - bool: true if the response is valid, false otherwise
//   - error: nil if valid, error details if validation fails
func checkMemcachedVersionResponse(response []byte) (bool, error) {
	// Minimum size for "VERSION \r\n" is 9 bytes
	if len(response) < 9 {
		return false, &utils.InvalidResponseErrorInfo{
			Service: MEMCACHED,
			Info:    "response too short for valid version response",
		}
	}

	responseStr := string(response)

	// Check if response starts with "VERSION "
	if !strings.HasPrefix(responseStr, "VERSION ") {
		return false, &utils.InvalidResponseErrorInfo{
			Service: MEMCACHED,
			Info:    "response does not start with 'VERSION '",
		}
	}

	// Check if response ends with \r\n
	if !strings.HasSuffix(responseStr, "\r\n") {
		return false, &utils.InvalidResponseErrorInfo{
			Service: MEMCACHED,
			Info:    "response does not end with \\r\\n",
		}
	}

	return true, nil
}

// checkMemcachedStatsResponse validates that the response is a valid Memcached
// stats command response.
//
// Expected format: Multiple "STAT <key> <value>\r\n" lines followed by "END\r\n"
//
// Parameters:
//   - response: The raw response bytes from the Memcached server
//
// Returns:
//   - bool: true if the response is valid, false otherwise
//   - error: nil if valid, error details if validation fails
func checkMemcachedStatsResponse(response []byte) (bool, error) {
	// Minimum size for "STAT x y\r\nEND\r\n" is 15 bytes
	if len(response) < 15 {
		return false, &utils.InvalidResponseErrorInfo{
			Service: MEMCACHED,
			Info:    "response too short for valid stats response",
		}
	}

	responseStr := string(response)

	// Check if response contains at least one STAT line
	if !strings.Contains(responseStr, "STAT ") {
		return false, &utils.InvalidResponseErrorInfo{
			Service: MEMCACHED,
			Info:    "response does not contain 'STAT ' lines",
		}
	}

	// Check if response ends with "END\r\n"
	if !strings.HasSuffix(responseStr, "END\r\n") {
		return false, &utils.InvalidResponseErrorInfo{
			Service: MEMCACHED,
			Info:    "response does not end with 'END\\r\\n'",
		}
	}

	return true, nil
}

// extractMemcachedVersion extracts the version string from a Memcached version response.
//
// Expected format: "VERSION <version>\r\n"
//
// Parameters:
//   - response: The raw response bytes from the version command
//
// Returns:
//   - string: The version string (e.g., "1.6.22"), or empty string if not found
func extractMemcachedVersion(response []byte) string {
	responseStr := string(response)

	// Remove "VERSION " prefix
	if !strings.HasPrefix(responseStr, "VERSION ") {
		return ""
	}

	version := strings.TrimPrefix(responseStr, "VERSION ")

	// Trim whitespace and line endings
	version = strings.TrimSpace(version)

	return version
}

// extractVersionFromStats extracts the version string from a Memcached stats response.
//
// Expected format: Contains a line "STAT version <version>\r\n"
//
// Parameters:
//   - response: The raw response bytes from the stats command
//
// Returns:
//   - string: The version string (e.g., "1.6.22"), or empty string if not found
func extractVersionFromStats(response []byte) string {
	responseStr := string(response)

	// Split response into lines
	lines := strings.Split(responseStr, "\r\n")

	// Find the "STAT version <version>" line
	for _, line := range lines {
		if strings.HasPrefix(line, "STAT version ") {
			// Extract version after "STAT version "
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return parts[2]
			}
		}
	}

	return ""
}

// buildMemcachedCPE constructs a CPE (Common Platform Enumeration) string for Memcached.
// CPE format: cpe:2.3:a:memcached:memcached:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" wildcard to match Wappalyzer/RMI/FTP plugin behavior
// and enable asset inventory use cases even without precise version information.
//
// Parameters:
//   - version: Memcached version string (e.g., "1.6.22"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" wildcard
func buildMemcachedCPE(version string) string {
	// Use wildcard for unknown versions (matches FTP/RMI/Wappalyzer pattern)
	if version == "" {
		version = "*"
	}

	// Memcached CPE template: cpe:2.3:a:memcached:memcached:{version}:*:*:*:*:*:*:*
	return fmt.Sprintf("cpe:2.3:a:memcached:memcached:%s:*:*:*:*:*:*:*", version)
}

// DetectMemcached performs Memcached fingerprinting using the text protocol.
//
// Detection Strategy:
//  1. DETECTION PHASE: Use version command to detect Memcached and extract version
//     - PRIMARY PATH: Send "version\r\n" command
//       Works on ALL Memcached versions (1.0+ to 1.6.x+)
//       Directly provides version string (100% confidence)
//  2. FALLBACK: If version command fails, try stats command
//     - Send "stats\r\n" command
//     - Extract version from "STAT version <version>" line
//
// Parameters:
//   - conn: Network connection to the Memcached server
//   - timeout: Timeout duration for network operations
//
// Returns:
//   - string: Version string if detected, empty string otherwise
//   - bool: true if this appears to be Memcached
//   - error: Error details if detection failed
func DetectMemcached(conn net.Conn, timeout time.Duration) (string, bool, error) {
	// PHASE 1: Try version command (PRIMARY)
	versionCmd := []byte("version\r\n")

	response, err := utils.SendRecv(conn, versionCmd, timeout)
	if err != nil {
		return "", false, err
	}
	if len(response) == 0 {
		return "", false, &utils.ServerNotEnable{}
	}

	// Check if response is a valid version response
	isValid, err := checkMemcachedVersionResponse(response)
	if isValid && err == nil {
		// Extract version from response
		version := extractMemcachedVersion(response)
		return version, true, nil
	}

	// PHASE 2: Try stats command (FALLBACK)
	statsCmd := []byte("stats\r\n")

	response, err = utils.SendRecv(conn, statsCmd, timeout)
	if err != nil {
		return "", false, err
	}
	if len(response) == 0 {
		return "", false, &utils.ServerNotEnable{}
	}

	// Check if response is a valid stats response
	isValid, err = checkMemcachedStatsResponse(response)
	if isValid && err == nil {
		// Extract version from stats output
		version := extractVersionFromStats(response)
		return version, true, nil
	}

	// Both detection methods failed
	return "", false, &utils.InvalidResponseError{Service: MEMCACHED}
}

func (p *MEMCACHEDPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	version, detected, err := DetectMemcached(conn, timeout)
	if !detected {
		return nil, err
	}

	// Memcached detected! Build service response
	payload := plugins.ServiceMemcached{
		Version: version,
	}

	// Always generate CPE - uses "*" for unknown version (matches FTP/RMI pattern)
	cpe := buildMemcachedCPE(version)
	payload.CPEs = []string{cpe}

	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *MEMCACHEDPlugin) PortPriority(port uint16) bool {
	return port == DEFAULT_PORT
}

func (p *MEMCACHEDPlugin) Name() string {
	return MEMCACHED
}

func (p *MEMCACHEDPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *MEMCACHEDPlugin) Priority() int {
	return 100
}
