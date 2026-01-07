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
Package sybase implements fingerprinting for Sybase ASE (Adaptive Server Enterprise),
now known as SAP ASE.

Sybase ASE uses the Tabular Data Stream (TDS) protocol version 5.0 for client-server
communication. While Microsoft SQL Server also uses TDS, Sybase's TDS 5.0 is not
compatible with Microsoft's TDS 7.x+ implementation.

Detection Strategy:
- Send TDS pre-login packet (similar to MSSQL)
- Validate TDS 5.0 response structure
- Check for Sybase/ASE markers in version string
- Differentiate from MSSQL via product identification

Version Detection:
- Extract version from TDS handshake VERSION option token
- Parse formats: "Adaptive Server Enterprise/{version}" or "Sybase SQL Server/{version}"
- Support Service Pack notation: "16.0 SP03" → "16.0.3"

CPE Generation:
- Vendor: sap (SAP acquired Sybase in 2010)
- Product: adaptive_server_enterprise
- Version: Extracted from handshake or "*" for unknown
*/
package sybase

import (
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

// TDS Option Token Constants
const (
	VERSION         uint32 = 0
	ENCRYPTION      uint32 = 1
	INSTOPT         uint32 = 2
	THREADID        uint32 = 3
	MARS            uint32 = 4
	TRACEID         uint32 = 5
	FEDAUTHREQUIRED uint32 = 6
	NONCEOPT        uint32 = 7
	TERMINATOR      byte   = 0xFF
)

// Protocol constants
const (
	SYBASE      = "sybase"
	DEFAULT_PORT = 5000
)

// OptionToken represents a TDS option token from pre-login response
type OptionToken struct {
	PLOptionToken  uint32
	PLOffset       uint32
	PLOptionLength uint32
	PLOptionData   []byte
}

// Data holds version information extracted from Sybase ASE
type Data struct {
	Version string
}

// SybasePlugin implements the Plugin interface for Sybase ASE fingerprinting
type SybasePlugin struct{}

// Version extraction patterns
var (
	// Pattern 1: "Adaptive Server Enterprise/16.0 SP03" → "16.0.3"
	aseWithSP = regexp.MustCompile(`Adaptive Server Enterprise/(\d+)\.(\d+)\s+SP(\d+)`)

	// Pattern 2: "Adaptive Server Enterprise/15.7.0 SP138" → "15.7.138"
	aseFullWithSP = regexp.MustCompile(`Adaptive Server Enterprise/(\d+)\.(\d+)\.(\d+)\s+SP(\d+)`)

	// Pattern 3: "Adaptive Server Enterprise/16.0" → "16.0"
	aseMajorMinor = regexp.MustCompile(`Adaptive Server Enterprise/(\d+\.\d+)`)

	// Pattern 4: "Sybase SQL Server/12.5.4" → "12.5.4" (legacy format)
	legacySybase = regexp.MustCompile(`Sybase SQL Server/(\d+\.\d+\.\d+)`)
)

func init() {
	plugins.RegisterPlugin(&SybasePlugin{})
}

// PortPriority returns true if the port is the default Sybase ASE port (5000)
func (p *SybasePlugin) PortPriority(port uint16) bool {
	return port == DEFAULT_PORT
}

// Name returns the protocol name for Sybase ASE
func (p *SybasePlugin) Name() string {
	return SYBASE
}

// Type returns the protocol type (TCP)
func (p *SybasePlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the execution priority (145 = after MSSQL 143, before generic)
func (p *SybasePlugin) Priority() int {
	return 145
}

// Run executes the Sybase ASE fingerprinting logic
func (p *SybasePlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Phase 1: Detection - send TDS pre-login and validate response
	data, detected, err := DetectSybase(conn, timeout)
	if !detected {
		return nil, err
	}

	// Phase 2: Enrichment - extract version and build CPE
	version := data.Version
	cpe := buildSybaseCPE(version)

	// Create service payload with CPE
	payload := plugins.ServiceSybase{
		CPEs:    []string{cpe},
		Version: version,
	}

	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

// DetectSybase sends a TDS pre-login packet and validates the Sybase ASE response
func DetectSybase(conn net.Conn, timeout time.Duration) (Data, bool, error) {
	// TDS pre-login packet (similar to MSSQL but interpreted for Sybase TDS 5.0)
	preLoginPacket := []byte{
		// Pre-Login Request Header
		0x12,       // Type: Pre-Login
		0x01,       // Status: EOM (End of Message)
		0x00, 0x58, // Length: 88 bytes
		0x00, 0x00, // SPID: 0
		0x01,       // PacketID: 1
		0x00,       // Window: 0

		// Pre-Login Request Body - Option Tokens
		// VERSION option
		0x00,       // PLOptionToken: VERSION
		0x00, 0x1F, // PLOffset: 31
		0x00, 0x06, // PLOptionLength: 6 bytes

		// ENCRYPTION option
		0x01,       // PLOptionToken: ENCRYPTION
		0x00, 0x25, // PLOffset: 37
		0x00, 0x01, // PLOptionLength: 1 byte

		// INSTOPT option
		0x02,       // PLOptionToken: INSTOPT
		0x00, 0x26, // PLOffset: 38
		0x00, 0x01, // PLOptionLength: 1 byte

		// THREADID option
		0x03,       // PLOptionToken: THREADID
		0x00, 0x27, // PLOffset: 39
		0x00, 0x04, // PLOptionLength: 4 bytes

		// MARS option
		0x04,       // PLOptionToken: MARS
		0x00, 0x2B, // PLOffset: 43
		0x00, 0x01, // PLOptionLength: 1 byte

		// TRACEID option
		0x05,       // PLOptionToken: TRACEID
		0x00, 0x2C, // PLOffset: 44
		0x00, 0x24, // PLOptionLength: 36 bytes

		0xFF, // TERMINATOR

		// PLOptionData (values for all options)
		0x11, 0x09, 0x00, 0x01, 0x00, 0x00, // VERSION data
		0x00,                               // ENCRYPTION data
		0x00,                               // INSTOPT data
		0x00, 0x00, 0x00, 0x00,             // THREADID data
		0x00,                               // MARS data
		// TRACEID data (36 bytes)
		0xF9, 0xB8, 0xCB, 0x5C, 0x94, 0x6B, 0x89, 0x1F,
		0xD9, 0xAA, 0x3C, 0x13, 0x4B, 0xD0, 0x7B, 0x88,
		0x03, 0x5C, 0x32, 0x21, 0x24, 0xA2, 0x81, 0x86,
		0x37, 0xCF, 0x62, 0x39, 0x4A, 0x46, 0x2C, 0xC6,
		0x00, 0x00, 0x00, 0x00,
	}

	// Send pre-login packet and receive response
	response, err := utils.SendRecv(conn, preLoginPacket, timeout)
	if err != nil {
		return Data{}, false, err
	}

	// Empty response = service not enabled
	if len(response) == 0 {
		return Data{}, false, &utils.ServerNotEnable{}
	}

	// Validate TDS response structure
	if err := validateTDSResponse(response); err != nil {
		return Data{}, false, err
	}

	// Parse option tokens from response
	optionTokens, err := parseTDSOptionTokens(response)
	if err != nil {
		return Data{}, false, err
	}

	// Extract version from VERSION option token
	version, isSybase := extractVersion(optionTokens)
	if !isSybase {
		// Not Sybase - might be MSSQL or other TDS server
		return Data{}, false, nil
	}

	return Data{Version: version}, true, nil
}

// validateTDSResponse validates the TDS packet header structure
func validateTDSResponse(response []byte) error {
	// Minimum TDS header is 8 bytes
	if len(response) < 8 {
		return &utils.InvalidResponseErrorInfo{
			Service: SYBASE,
			Info:    "response too short for TDS packet header",
		}
	}

	// Check packet type (0x04 = Tabular Response)
	if response[0] != 0x04 {
		return &utils.InvalidResponseErrorInfo{
			Service: SYBASE,
			Info:    "packet type should be 0x04 (tabular response)",
		}
	}

	// Check status (0x01 = EOM - End of Message)
	if response[1] != 0x01 {
		return &utils.InvalidResponseErrorInfo{
			Service: SYBASE,
			Info:    "packet status should be 0x01 (EOM)",
		}
	}

	// Validate packet length matches actual response length
	packetLength := int(binary.BigEndian.Uint16(response[2:4]))
	if len(response) != packetLength {
		return &utils.InvalidResponseErrorInfo{
			Service: SYBASE,
			Info:    fmt.Sprintf("packet length mismatch: declared %d, actual %d", packetLength, len(response)),
		}
	}

	// SPID should be zero
	if response[4] != 0x00 || response[5] != 0x00 {
		return &utils.InvalidResponseErrorInfo{
			Service: SYBASE,
			Info:    "SPID should be zero in pre-login response",
		}
	}

	// PacketID should be 1
	if response[6] != 0x01 {
		return &utils.InvalidResponseErrorInfo{
			Service: SYBASE,
			Info:    "PacketID should be 1",
		}
	}

	// Window should be zero
	if response[7] != 0x00 {
		return &utils.InvalidResponseErrorInfo{
			Service: SYBASE,
			Info:    "Window should be zero",
		}
	}

	return nil
}

// parseTDSOptionTokens extracts option tokens from TDS response body
func parseTDSOptionTokens(response []byte) ([]OptionToken, error) {
	// Option tokens start at byte 8 (after header)
	position := 8
	var optionTokens []OptionToken

	// Parse option tokens until TERMINATOR (0xFF)
	for position < len(response) && response[position] != TERMINATOR {
		// Ensure we have enough bytes for a full option token (5 bytes)
		if position+5 > len(response) {
			return nil, &utils.InvalidResponseErrorInfo{
				Service: SYBASE,
				Info:    "truncated option token",
			}
		}

		// Parse option token fields
		plOptionToken := uint32(response[position])
		plOffset := uint32(binary.BigEndian.Uint16(response[position+1 : position+3]))
		plOptionLength := uint32(binary.BigEndian.Uint16(response[position+3 : position+5]))

		// Extract option data
		var plOptionData []byte
		if plOptionLength > 0 {
			dataStart := 8 + plOffset // Offset is relative to body start (after header)
			dataEnd := dataStart + plOptionLength

			if dataEnd > uint32(len(response)) {
				return nil, &utils.InvalidResponseErrorInfo{
					Service: SYBASE,
					Info:    "option token data extends beyond packet",
				}
			}

			plOptionData = response[dataStart:dataEnd]
		}

		// Add token to list
		optionTokens = append(optionTokens, OptionToken{
			PLOptionToken:  plOptionToken,
			PLOffset:       plOffset,
			PLOptionLength: plOptionLength,
			PLOptionData:   plOptionData,
		})

		// Move to next token (each token header is 5 bytes)
		position += 5
	}

	// Verify terminator found
	if position >= len(response) || response[position] != TERMINATOR {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: SYBASE,
			Info:    "option token list not terminated by 0xFF",
		}
	}

	// VERSION token is required (should be first)
	if len(optionTokens) < 1 {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: SYBASE,
			Info:    "no option tokens found, VERSION is required",
		}
	}

	return optionTokens, nil
}

// extractVersion extracts version string from option tokens and determines if it's Sybase
func extractVersion(optionTokens []OptionToken) (string, bool) {
	// Find VERSION option token (PLOptionToken = 0)
	var versionData []byte
	for _, token := range optionTokens {
		if token.PLOptionToken == VERSION {
			versionData = token.PLOptionData
			break
		}
	}

	// No version data = cannot determine if Sybase
	if len(versionData) == 0 {
		return "", false
	}

	// Convert version data to string (may contain null-terminated version string)
	versionStr := string(versionData)

	// Check for Sybase/ASE markers
	isSybase := strings.Contains(versionStr, "Sybase") ||
		strings.Contains(versionStr, "Adaptive Server Enterprise") ||
		strings.Contains(versionStr, "Adaptive Server") ||
		strings.Contains(versionStr, "SAP ASE")

	// Explicitly check NOT MSSQL
	if strings.Contains(versionStr, "Microsoft") {
		return "", false
	}

	// If not identifiable as Sybase, return false
	if !isSybase {
		return "", false
	}

	// Parse version using regex patterns
	version := parseVersionString(versionStr)

	return version, true
}

// parseVersionString extracts semantic version from Sybase version string
func parseVersionString(versionStr string) string {
	// Pattern 1: "Adaptive Server Enterprise/16.0 SP03" → "16.0.3"
	if matches := aseWithSP.FindStringSubmatch(versionStr); len(matches) >= 4 {
		major := matches[1]
		minor := matches[2]
		spStr := matches[3]
		// Convert SP string to int and back to remove leading zeros
		if spNum, err := strconv.Atoi(spStr); err == nil {
			return fmt.Sprintf("%s.%s.%d", major, minor, spNum)
		}
		// Fallback if conversion fails
		return fmt.Sprintf("%s.%s.%s", major, minor, spStr)
	}

	// Pattern 2: "Adaptive Server Enterprise/15.7.0 SP138" → "15.7.138"
	if matches := aseFullWithSP.FindStringSubmatch(versionStr); len(matches) >= 5 {
		major := matches[1]
		minor := matches[2]
		// patch := matches[3] // Not used in this format, SP number replaces patch
		spStr := matches[4]
		// Convert SP string to int and back to remove leading zeros
		if spNum, err := strconv.Atoi(spStr); err == nil {
			return fmt.Sprintf("%s.%s.%d", major, minor, spNum)
		}
		// Fallback if conversion fails
		return fmt.Sprintf("%s.%s.%s", major, minor, spStr)
	}

	// Pattern 3: "Adaptive Server Enterprise/16.0" → "16.0"
	if matches := aseMajorMinor.FindStringSubmatch(versionStr); len(matches) >= 2 {
		return matches[1]
	}

	// Pattern 4: "Sybase SQL Server/12.5.4" → "12.5.4"
	if matches := legacySybase.FindStringSubmatch(versionStr); len(matches) >= 2 {
		return matches[1]
	}

	// No version extracted = return empty string (will use wildcard in CPE)
	return ""
}

// buildSybaseCPE generates a CPE (Common Platform Enumeration) string for Sybase ASE
//
// Uses wildcard version ("*") when version is unknown to match Wappalyzer/RMI/FTP plugin
// behavior and enable asset inventory use cases even without precise version information.
//
// CPE format: cpe:2.3:a:sap:adaptive_server_enterprise:{version}:*:*:*:*:*:*:*
//
// Parameters:
//   - version: Version string (e.g., "16.0.3"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" wildcard
func buildSybaseCPE(version string) string {
	// Trim whitespace
	version = strings.TrimSpace(version)

	// Use wildcard for unknown versions (matches FTP/RMI/Wappalyzer pattern)
	if version == "" {
		version = "*"
	}

	// Sybase ASE CPE template (vendor: sap, product: adaptive_server_enterprise)
	cpeTemplate := "cpe:2.3:a:sap:adaptive_server_enterprise:%s:*:*:*:*:*:*:*"

	return fmt.Sprintf(cpeTemplate, version)
}
