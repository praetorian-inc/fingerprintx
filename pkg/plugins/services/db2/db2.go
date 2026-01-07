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

package db2

import (
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

/*
IBM DB2 Fingerprinting via DRDA Protocol

This plugin implements DB2 fingerprinting using the DRDA (Distributed Relational
Database Architecture) protocol. DRDA is a binary protocol used by IBM DB2,
Apache Derby, and IBM Informix for database communications.

Detection Strategy:
  PHASE 1 - DETECTION (determines if the service is DB2):
    - Send EXCSAT (Exchange Server Attributes) message
    - Receive EXCSATRD (EXCSAT Reply) from server
    - Validate DDM (Distributed Data Management) structure
    - Check for DB2-specific markers in response parameters

  PHASE 2 - ENRICHMENT (attempts to retrieve version information):
    - Parse EXTNAM parameter (External Name) for version string
    - Fallback: Parse SRVRLSLV parameter (Server Release Level)
    - Generate CPE with extracted version or "*" for unknown

DRDA Wire Protocol (DDM Message Structure):

DDM Header (10+ bytes):
  Offset 0-1: Length (16-bit big-endian, includes length field itself)
  Offset 2:   Magic (0xD0 for DDM messages)
  Offset 3:   Format flags
  Offset 4-5: Codepoint (16-bit big-endian, identifies command/reply type)
  Offset 6+:  Parameters (optional, depends on codepoint)

DDM Parameter Structure:
  Offset 0-1: Parameter length (16-bit big-endian)
  Offset 2-3: Parameter codepoint (16-bit big-endian)
  Offset 4+:  Parameter data

Key Codepoints:
  EXCSAT   = 0x1041 (Exchange Server Attributes - client request)
  EXCSATRD = 0x1443 (EXCSAT Reply - server response)
  EXTNAM   = 0x115E (External Name - server identification string)
  SRVRLSLV = 0x2454 (Server Release Level - version encoding)
  SRVNAM   = 0x2434 (Server Name - instance name)
  MGRLVLLS = 0x1404 (Manager Level List - protocol versions supported)

EXCSATRD Response Parameters:
  - EXTNAM: Contains human-readable server identification
    Example: "DB2/LINUXX8664 11.5.6.0" (DB2 on Linux x86-64, version 11.5.6.0)
    Example: "Apache Derby Network Server" (Derby, not DB2)
  - SRVRLSLV: Contains encoded version in format "SQLvvrrm"
    Example: "SQL11056" = DB2 11.5.6
  - SRVNAM: Contains server instance name (may be custom)

DB2 vs Derby vs Informix Differentiation:
  - DB2:      EXTNAM contains "DB2/" or "DB2 "
  - Derby:    EXTNAM contains "Derby"
  - Informix: EXTNAM contains "Informix"

Version Extraction:
  1. Try EXTNAM parameter (most reliable, human-readable)
  2. Fallback to SRVRLSLV parameter (encoded, requires parsing)
  3. If neither available, CPE uses "*" wildcard for version

Default Ports:
  - 50000: DB2 on Linux/Unix/Windows (LUW)
  - 446:   DB2 on AS/400/iSeries (older platforms)

References:
  - IBM DRDA Documentation: https://www.ibm.com/docs/en/db2/11.5.x?topic=drda-db2-connect
  - DRDA Specification: https://pubs.opengroup.org/onlinepubs/9699939399/toc.pdf
  - Wireshark DRDA Dissector: https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-drda.c
  - Nmap DRDA Library: https://nmap.org/nsedoc/lib/drda.html
*/

type DB2Plugin struct{}

const DB2 = "db2"

// DDM and DRDA constants
const (
	DDM_MAGIC   = 0xD0   // Magic byte for DDM messages
	EXCSAT      = 0x1041 // Exchange Server Attributes (client → server)
	EXCSATRD    = 0x1443 // EXCSAT Reply (server → client)
	EXTNAM      = 0x115E // External Name (server identification)
	SRVRLSLV    = 0x2454 // Server Release Level (version encoding)
	SRVNAM      = 0x2434 // Server Name (instance name)
	MGRLVLLS    = 0x1404 // Manager Level List
	MIN_DDM_LEN = 10     // Minimum DDM message length
)

// db2Metadata holds enriched metadata extracted from EXCSATRD response
type db2Metadata struct {
	ServerName string // DB2 instance name (from SRVNAM parameter)
	Version    string // DB2 version string (e.g., "11.5.6.0") - only if explicitly returned
	ServerType string // "DB2", "Derby", or "Informix"
}

// Version extraction regex patterns
var (
	// EXTNAM version extraction: "DB2/LINUXX8664 11.5.6.0" → "11.5.6.0"
	extnamVersionRegex = regexp.MustCompile(`(\d+\.\d+\.\d+(?:\.\d+)?)`)

	// SRVRLSLV decoding: "SQL11056" → "11.5.6"
	srvrlslvRegex = regexp.MustCompile(`^SQL(\d{2})(\d{2})(\d+)`)
)

func init() {
	plugins.RegisterPlugin(&DB2Plugin{})
}

// buildEXCSAT constructs a minimal EXCSAT message to initiate DRDA handshake.
//
// The EXCSAT message contains client attributes that the server can use to
// identify the connecting client. For fingerprinting, we send minimal required
// parameters to reduce message size and avoid unnecessary complexity.
//
// Message structure:
//   DDM Header (10 bytes):
//     Length: 2 bytes (big-endian, total message length)
//     Magic: 1 byte (0xD0)
//     Format: 1 byte (0x01 = chained DSS, RQSDSS format)
//     Codepoint: 2 bytes (0x1041 = EXCSAT)
//     Correlation ID: 2 bytes (0x0001)
//     Length2: 2 bytes (length - 6, per DRDA spec)
//
//   Parameters:
//     EXTNAM (External Name): Client identification
//       - Length: 2 bytes
//       - Codepoint: 2 bytes (0x115E)
//       - Data: ASCII string "fingerprintx"
//
// Returns:
//   []byte: Properly formatted EXCSAT message ready to send
func buildEXCSAT() []byte {
	// Client external name (identifies us as "fingerprintx")
	extnam := []byte("fingerprintx")

	// Calculate parameter length: length field (2) + codepoint (2) + data length
	extnameParamLen := uint16(2 + 2 + len(extnam))

	// Calculate total message length: header (10) + param length
	totalLen := uint16(10 + int(extnameParamLen))

	msg := make([]byte, 0, totalLen)

	// DDM Header (10 bytes)
	msg = append(msg, byte(totalLen>>8), byte(totalLen))    // Length (big-endian)
	msg = append(msg, DDM_MAGIC)                            // Magic (0xD0)
	msg = append(msg, 0x01)                                 // Format (chained DSS, RQSDSS)
	msg = append(msg, byte(EXCSAT>>8&0xFF), byte(EXCSAT&0xFF))        // Codepoint (0x1041)
	msg = append(msg, 0x00, 0x01)                           // Correlation ID
	lengthParam := totalLen - 6                             // Length2 (per DRDA spec)
	msg = append(msg, byte(lengthParam>>8), byte(lengthParam))

	// EXTNAM parameter
	msg = append(msg, byte(extnameParamLen>>8), byte(extnameParamLen)) // Param length
	msg = append(msg, byte(EXTNAM>>8&0xFF), byte(EXTNAM&0xFF))                   // Param codepoint (0x115E)
	msg = append(msg, extnam...)                                       // Param data

	return msg
}

// checkDDMResponse validates that the response is a valid DDM message structure.
//
// Validation checks:
//  1. Minimum length (10 bytes for DDM header)
//  2. Magic byte (0xD0 indicates DDM message)
//  3. Declared length matches actual response length
//  4. Codepoint matches expected value (0x1443 for EXCSATRD)
//
// Parameters:
//   - response: The raw response bytes from the DB2 server
//   - expectedCodepoint: The codepoint we expect (0x1443 for EXCSATRD)
//
// Returns:
//   - bool: true if response is valid DDM message
//   - error: nil if valid, error details if validation fails
func checkDDMResponse(response []byte, expectedCodepoint uint16) (bool, error) {
	// Check minimum length (DDM header is 10 bytes)
	if len(response) < MIN_DDM_LEN {
		return false, &utils.InvalidResponseErrorInfo{
			Service: DB2,
			Info:    fmt.Sprintf("response too short: got %d bytes, need at least %d", len(response), MIN_DDM_LEN),
		}
	}

	// Check magic byte at offset 2
	if response[2] != DDM_MAGIC {
		return false, &utils.InvalidResponseErrorInfo{
			Service: DB2,
			Info:    fmt.Sprintf("invalid DDM magic byte: expected 0x%02X, got 0x%02X", DDM_MAGIC, response[2]),
		}
	}

	// Extract and validate message length (offset 0-1, big-endian)
	declaredLen := binary.BigEndian.Uint16(response[0:2])
	if declaredLen < MIN_DDM_LEN || int(declaredLen) > len(response) {
		return false, &utils.InvalidResponseErrorInfo{
			Service: DB2,
			Info:    fmt.Sprintf("invalid message length: declared %d, actual %d", declaredLen, len(response)),
		}
	}

	// Extract and validate codepoint (offset 4-5, big-endian)
	codepoint := binary.BigEndian.Uint16(response[4:6])
	if codepoint != expectedCodepoint {
		return false, &utils.InvalidResponseErrorInfo{
			Service: DB2,
			Info:    fmt.Sprintf("unexpected codepoint: expected 0x%04X, got 0x%04X", expectedCodepoint, codepoint),
		}
	}

	return true, nil
}

// extractParameter extracts a parameter value from a DDM message by codepoint.
//
// DDM messages contain zero or more parameters, each with this structure:
//   Offset 0-1: Parameter length (big-endian, includes length field + codepoint)
//   Offset 2-3: Parameter codepoint (big-endian, identifies parameter type)
//   Offset 4+:  Parameter data
//
// Parameters:
//   - response: DDM message bytes (starting from first parameter, skip 10-byte header)
//   - targetCodepoint: The codepoint to search for (e.g., 0x115E for EXTNAM)
//
// Returns:
//   - []byte: Parameter data if found, nil otherwise
func extractParameter(response []byte, targetCodepoint uint16) []byte {
	// Start after DDM header (10 bytes)
	offset := 10
	responseLen := len(response)

	for offset+4 <= responseLen { // Need at least 4 bytes for param header
		// Extract parameter length (big-endian)
		paramLen := binary.BigEndian.Uint16(response[offset : offset+2])

		// Extract parameter codepoint (big-endian)
		paramCodepoint := binary.BigEndian.Uint16(response[offset+2 : offset+4])

		// Check if we found the target parameter
		if paramCodepoint == targetCodepoint {
			// Calculate data start and end
			dataStart := offset + 4
			dataEnd := offset + int(paramLen)

			// Validate bounds
			if dataEnd > responseLen {
				return nil // Truncated parameter
			}

			// Return parameter data (excluding length and codepoint)
			return response[dataStart:dataEnd]
		}

		// Move to next parameter
		offset += int(paramLen)

		// Sanity check to prevent infinite loop
		if paramLen < 4 {
			break // Invalid parameter length, stop parsing
		}
	}

	return nil // Parameter not found
}

// extractEXTNAM extracts the EXTNAM (External Name) parameter from EXCSATRD response.
//
// EXTNAM contains a human-readable server identification string, such as:
//   - "DB2/LINUXX8664 11.5.6.0" (DB2 on Linux x86-64, version 11.5.6.0)
//   - "Apache Derby Network Server" (Apache Derby)
//   - "Informix Dynamic Server" (IBM Informix)
//
// This is the primary method for identifying the database product and version.
//
// Parameters:
//   - response: EXCSATRD response bytes
//
// Returns:
//   - string: EXTNAM value if found, empty string otherwise
func extractEXTNAM(response []byte) string {
	data := extractParameter(response, EXTNAM)
	if data == nil {
		return ""
	}

	// Convert bytes to string (ASCII or EBCDIC, handle both)
	// For simplicity, treat as ASCII first
	return string(data)
}

// extractSRVRLSLV extracts the SRVRLSLV (Server Release Level) parameter.
//
// SRVRLSLV contains an encoded version string in format "SQLvvrrm" where:
//   vv = Major version (2 digits)
//   rr = Minor version (2 digits)
//   m  = Modification level (1+ digits)
//
// Examples:
//   "SQL11056" → 11.5.6
//   "SQL10050" → 10.5.0
//   "SQL09074" → 9.7.4
//
// Parameters:
//   - response: EXCSATRD response bytes
//
// Returns:
//   - string: SRVRLSLV value if found, empty string otherwise
func extractSRVRLSLV(response []byte) string {
	data := extractParameter(response, SRVRLSLV)
	if data == nil {
		return ""
	}
	return string(data)
}

// extractServerName extracts the SRVNAM (Server Name) parameter.
//
// SRVNAM contains the DB2 instance name (e.g., "DB2", "SAMPLE", or custom name).
//
// Parameters:
//   - response: EXCSATRD response bytes
//
// Returns:
//   - string: SRVNAM value if found, empty string otherwise
func extractServerName(response []byte) string {
	data := extractParameter(response, SRVNAM)
	if data == nil {
		return ""
	}
	return string(data)
}

// parseEXTNAMVersion extracts version string from EXTNAM parameter.
//
// EXTNAM typically contains version in format "ProductName X.Y.Z.W" or "ProductName X.Y.Z".
// We use regex to extract the numeric version portion.
//
// Examples:
//   "DB2/LINUXX8664 11.5.6.0" → "11.5.6.0"
//   "DB2 for z/OS 12.1.0" → "12.1.0"
//
// Parameters:
//   - extnam: EXTNAM string value
//
// Returns:
//   - string: Extracted version, or empty string if not found
func parseEXTNAMVersion(extnam string) string {
	matches := extnamVersionRegex.FindStringSubmatch(extnam)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

// decodeSRVRLSLV decodes the SRVRLSLV version encoding.
//
// Format: "SQLvvrrm" where vv=major, rr=minor, m=modification
//
// Examples:
//   "SQL11056" → "11.5.6"
//   "SQL10050" → "10.5.0"
//   "SQL09074" → "9.7.4"
//
// Parameters:
//   - srvrlslv: SRVRLSLV string value
//
// Returns:
//   - string: Decoded version, or empty string if format invalid
func decodeSRVRLSLV(srvrlslv string) string {
	matches := srvrlslvRegex.FindStringSubmatch(srvrlslv)
	if len(matches) >= 4 {
		// Convert to integers to remove leading zeros, then back to strings
		var major, minor, mod int
		fmt.Sscanf(matches[1], "%d", &major)
		fmt.Sscanf(matches[2], "%d", &minor)
		fmt.Sscanf(matches[3], "%d", &mod)
		return fmt.Sprintf("%d.%d.%d", major, minor, mod)
	}
	return ""
}

// identifyServerType determines if the server is DB2, Derby, or Informix based on EXTNAM.
//
// Detection logic:
//   - If EXTNAM contains "DB2/" or "DB2 " → IBM DB2
//   - If EXTNAM contains "Derby" → Apache Derby
//   - If EXTNAM contains "Informix" → IBM Informix
//   - Otherwise → "unknown"
//
// Parameters:
//   - extnam: EXTNAM string value
//
// Returns:
//   - string: "DB2", "Derby", "Informix", or "unknown"
func identifyServerType(extnam string) string {
	extnameUpper := strings.ToUpper(extnam)

	if strings.Contains(extnameUpper, "DB2/") || strings.Contains(extnameUpper, "DB2 ") {
		return "DB2"
	}
	if strings.Contains(extnameUpper, "DERBY") {
		return "Derby"
	}
	if strings.Contains(extnameUpper, "INFORMIX") {
		return "Informix"
	}
	return "unknown"
}

// parseEXCSATRDMetadata extracts complete metadata from EXCSATRD response.
//
// Extraction priority for version:
//  1. EXTNAM parameter (most reliable, human-readable)
//  2. SRVRLSLV parameter (encoded, requires decoding)
//  3. Neither available → empty version (CPE will use "*")
//
// Parameters:
//   - response: EXCSATRD response bytes
//
// Returns:
//   - db2Metadata: Extracted metadata (ServerName, Version, ServerType)
func parseEXCSATRDMetadata(response []byte) db2Metadata {
	metadata := db2Metadata{
		ServerType: "unknown",
	}

	// Extract EXTNAM (primary method for identification and version)
	extnam := extractEXTNAM(response)
	if extnam != "" {
		// Identify server type (DB2 vs Derby vs Informix)
		metadata.ServerType = identifyServerType(extnam)

		// Extract version from EXTNAM
		version := parseEXTNAMVersion(extnam)
		if version != "" {
			metadata.Version = version
		}
	}

	// Fallback: Try SRVRLSLV if version not found in EXTNAM
	if metadata.Version == "" {
		srvrlslv := extractSRVRLSLV(response)
		if srvrlslv != "" {
			version := decodeSRVRLSLV(srvrlslv)
			if version != "" {
				metadata.Version = version
			}
		}
	}

	// Extract server name (instance name)
	serverName := extractServerName(response)
	if serverName != "" {
		metadata.ServerName = serverName
	}

	return metadata
}

// DetectDB2 performs DB2 fingerprinting using DRDA handshake.
//
// Detection flow:
//  1. Build and send EXCSAT message
//  2. Receive EXCSATRD response from server
//  3. Validate DDM structure and EXCSATRD codepoint
//  4. Extract metadata (server type, version, instance name)
//  5. Return detection result
//
// Parameters:
//   - conn: Network connection to the database server
//   - timeout: Timeout duration for network operations
//
// Returns:
//   - db2Metadata: Extracted metadata (if detected)
//   - bool: true if DRDA server detected (not necessarily DB2)
//   - error: Error details if detection failed
func DetectDB2(conn net.Conn, timeout time.Duration) (db2Metadata, bool, error) {
	// Build EXCSAT message
	excsat := buildEXCSAT()

	// Send EXCSAT and receive response
	response, err := utils.SendRecv(conn, excsat, timeout)
	if err != nil {
		return db2Metadata{}, false, err
	}

	if len(response) == 0 {
		return db2Metadata{}, false, &utils.InvalidResponseError{Service: DB2}
	}

	// Validate DDM structure and check for EXCSATRD codepoint
	isValid, err := checkDDMResponse(response, EXCSATRD)
	if !isValid {
		return db2Metadata{}, false, err
	}

	// Parse metadata from EXCSATRD response
	metadata := parseEXCSATRDMetadata(response)

	return metadata, true, nil
}

// buildDB2CPE constructs a CPE (Common Platform Enumeration) string for DB2.
//
// CPE format: cpe:2.3:a:ibm:db2:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to match Wappalyzer/RMI/FTP
// plugin behavior and enable asset inventory use cases.
//
// Parameters:
//   - version: DB2 version string (e.g., "11.5.6.0"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" for unknown version
func buildDB2CPE(version string) string {
	if version == "" {
		version = "*" // Unknown version, but known product (matches RMI/FTP/Wappalyzer pattern)
	}
	return fmt.Sprintf("cpe:2.3:a:ibm:db2:%s:*:*:*:*:*:*:*", version)
}

func (p *DB2Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	metadata, detected, err := DetectDB2(conn, timeout)
	if detected && err != nil {
		// Server responded but with non-fatal error, return nil (not DB2)
		return nil, nil
	} else if detected && err == nil {
		// Successfully detected DRDA server

		// Only return DB2 if server type is confirmed as DB2
		if metadata.ServerType != "DB2" {
			// This is Derby, Informix, or unknown DRDA server - not DB2
			return nil, nil
		}

		// Confirmed DB2 server
		payload := plugins.ServiceDB2{
			ServerName: metadata.ServerName,
		}

		// Always generate CPE - uses "*" for unknown version (matches FTP/RMI pattern)
		cpe := buildDB2CPE(metadata.Version)
		payload.CPEs = []string{cpe}

		return plugins.CreateServiceFrom(target, payload, false, metadata.Version, plugins.TCP), nil
	}

	// Detection failed
	return nil, err
}

func (p *DB2Plugin) PortPriority(port uint16) bool {
	return port == 50000 || port == 446
}

func (p *DB2Plugin) Name() string {
	return DB2
}

func (p *DB2Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *DB2Plugin) Priority() int {
	return 120
}
