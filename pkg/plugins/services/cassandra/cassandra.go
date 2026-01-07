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

package cassandra

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

/*
Apache Cassandra CQL Native Protocol Fingerprinting

This plugin implements Cassandra fingerprinting using the CQL native protocol
(default port 9042) with OPTIONS/SUPPORTED handshake for protocol detection
and version extraction.

Detection Strategy:
  PHASE 1 - DETECTION (determines if the service is Cassandra):
    - Send OPTIONS frame (opcode 0x05) with protocol v4
    - Validate SUPPORTED response (opcode 0x06)
    - Check frame structure (9-byte header, big-endian encoding)

  PHASE 2 - ENRICHMENT (extracts version and metadata):
    - Parse SUPPORTED multimap body (string multimap format)
    - Extract CQL_VERSION (primary version marker)
    - Extract PROTOCOL_VERSIONS (secondary version marker)
    - Extract COMPRESSION (tertiary marker: zstd = Cassandra 4.0+)
    - Build CPE (use `*` for unknown version, matching MongoDB/FTP pattern)

CQL Native Protocol Frame Structure:
  Header (9 bytes, big-endian):
    - version (1 byte): 0x04 (request), 0x84 (response)
    - flags (1 byte): Compression, tracing, custom payload, warnings
    - stream (2 bytes): Stream ID for multiplexing
    - opcode (1 byte): Message type (OPTIONS=0x05, SUPPORTED=0x06)
    - length (4 bytes): Body length in bytes

  Body (variable):
    - For OPTIONS: empty (length=0)
    - For SUPPORTED: string multimap with keys:
      * CQL_VERSION: ["3.4.5"], ["3.4.6"], ["3.4.7"]
      * COMPRESSION: ["lz4", "snappy"], ["lz4", "snappy", "zstd"]
      * PROTOCOL_VERSIONS: ["3/v3", "4/v4", "5/v5"]

Version Mapping:
  - CQL 3.4.7 → Cassandra 5.0.x
  - CQL 3.4.6 → Cassandra 4.1.x
  - CQL 3.4.5 → Cassandra 4.0.x
  - CQL 3.4.4 → Cassandra 3.10-3.11.x
  - Protocol v5 → Cassandra 4.0+
  - Compression zstd → Cassandra 4.0+
*/

type CassandraPlugin struct{}

const CASSANDRA = "cassandra"

// Cassandra metadata holds enriched information extracted from SUPPORTED response
type cassandraMetadata struct {
	Product          string   // "Apache Cassandra", "ScyllaDB", "DataStax Enterprise"
	Version          string   // Cassandra version (e.g., "4.0", "5.0")
	Confidence       string   // "high", "medium", "low"
	CQLVersion       string   // CQL version from SUPPORTED response
	ProtocolVersions []string // Protocol versions supported
	Compression      []string // Compression algorithms supported
}

// CQL protocol opcodes
const (
	OP_OPTIONS   = 0x05
	OP_SUPPORTED = 0x06
)

// Protocol version bytes
const (
	PROTOCOL_V4_REQUEST  = 0x04
	PROTOCOL_V4_RESPONSE = 0x84
	PROTOCOL_V5_REQUEST  = 0x05
	PROTOCOL_V5_RESPONSE = 0x85
	PROTOCOL_V6_REQUEST  = 0x06
	PROTOCOL_V6_RESPONSE = 0x86
)

func init() {
	plugins.RegisterPlugin(&CassandraPlugin{})
}

// buildOPTIONSFrame constructs a CQL OPTIONS request frame.
// OPTIONS is sent before STARTUP to query server capabilities without authentication.
//
// Frame structure (13 bytes):
//   [version|flags|stream|opcode|length]
//   [0x04   |0x00 |0x0000|0x05  |0x00000000]
//
// Returns:
//   - []byte: Complete OPTIONS frame ready to send
func buildOPTIONSFrame() []byte {
	return []byte{
		PROTOCOL_V4_REQUEST, // version: v4 request
		0x00,                // flags: none
		0x00, 0x00,          // stream: 0
		OP_OPTIONS,          // opcode: OPTIONS
		0x00, 0x00, 0x00, 0x00, // length: 0 (empty body)
	}
}

// isCassandraSUPPORTED validates that the response is a valid Cassandra SUPPORTED frame.
//
// Validation layers:
//  1. Minimum length (9-byte header + 5-byte minimal multimap)
//  2. Version byte (response direction: 0x83-0x86 for v3-v6 responses)
//  3. Stream ID matches request (should be 0)
//  4. Opcode is SUPPORTED (0x06)
//  5. Length field is reasonable (<1MB)
//
// Parameters:
//   - response: Raw response bytes from Cassandra server
//   - requestStream: Expected stream ID from request (typically 0)
//
// Returns:
//   - bool: true if valid SUPPORTED frame, false otherwise
//   - error: nil if valid, error details if validation fails
func isCassandraSUPPORTED(response []byte, requestStream uint16) (bool, error) {
	// Minimum: header (9 bytes) + minimal multimap (5 bytes) = 14 bytes
	if len(response) < 14 {
		return false, &utils.InvalidResponseErrorInfo{
			Service: CASSANDRA,
			Info:    "response too short for valid SUPPORTED frame",
		}
	}

	// Check version byte: 0x83-0x86 (response direction + v3-v6)
	version := response[0]
	if version < 0x83 || version > 0x86 {
		return false, &utils.InvalidResponseErrorInfo{
			Service: CASSANDRA,
			Info:    fmt.Sprintf("invalid version byte, expected 0x83-0x86, got 0x%02x", version),
		}
	}

	// Check stream matches request
	stream := binary.BigEndian.Uint16(response[2:4])
	if stream != requestStream {
		return false, &utils.InvalidResponseErrorInfo{
			Service: CASSANDRA,
			Info:    fmt.Sprintf("stream mismatch, expected %d, got %d", requestStream, stream),
		}
	}

	// Check opcode is SUPPORTED (0x06)
	opcode := response[4]
	if opcode != OP_SUPPORTED {
		return false, &utils.InvalidResponseErrorInfo{
			Service: CASSANDRA,
			Info:    fmt.Sprintf("invalid opcode, expected 0x06 (SUPPORTED), got 0x%02x", opcode),
		}
	}

	// Check length field is reasonable (max 1MB for SUPPORTED)
	length := binary.BigEndian.Uint32(response[5:9])
	if length < 5 || length > 1024*1024 {
		return false, &utils.InvalidResponseErrorInfo{
			Service: CASSANDRA,
			Info:    fmt.Sprintf("invalid length field: %d", length),
		}
	}

	// Check actual response length matches declared length
	if len(response) < int(9+length) {
		return false, &utils.InvalidResponseErrorInfo{
			Service: CASSANDRA,
			Info:    "response shorter than declared length",
		}
	}

	return true, nil
}

// parseString extracts a CQL [string] from bytes at given offset.
// CQL string format: [short length][bytes]
//
// Parameters:
//   - data: Byte slice containing the string
//   - offset: Starting position
//
// Returns:
//   - string: Extracted string value
//   - int: New offset after the string
//   - error: nil if successful, error if data truncated
func parseString(data []byte, offset int) (string, int, error) {
	if offset+2 > len(data) {
		return "", offset, fmt.Errorf("truncated string length at offset %d", offset)
	}

	strLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if offset+int(strLen) > len(data) {
		return "", offset, fmt.Errorf("truncated string body at offset %d", offset)
	}

	str := string(data[offset : offset+int(strLen)])
	offset += int(strLen)

	return str, offset, nil
}

// parseStringList extracts a CQL [string list] from bytes at given offset.
// Format: [short n][string1][string2]...[stringN]
//
// Parameters:
//   - data: Byte slice containing the string list
//   - offset: Starting position
//
// Returns:
//   - []string: List of extracted strings
//   - int: New offset after the list
//   - error: nil if successful, error if data truncated
func parseStringList(data []byte, offset int) ([]string, int, error) {
	if offset+2 > len(data) {
		return nil, offset, fmt.Errorf("truncated string list count at offset %d", offset)
	}

	count := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	list := make([]string, 0, count)
	for i := 0; i < int(count); i++ {
		str, newOffset, err := parseString(data, offset)
		if err != nil {
			return nil, offset, err
		}
		list = append(list, str)
		offset = newOffset
	}

	return list, offset, nil
}

// parseSUPPORTEDMultimap extracts key-value pairs from SUPPORTED response body.
//
// Multimap format: [short n][key1][list1]...[keyN][listN]
// Each entry: [string key][string list values]
//
// Parameters:
//   - response: Complete SUPPORTED response (header + body)
//
// Returns:
//   - map[string][]string: Multimap of capabilities
//   - error: nil if successful, error if parsing fails
func parseSUPPORTEDMultimap(response []byte) (map[string][]string, error) {
	// SUPPORTED body starts after 9-byte header
	if len(response) < 9 {
		return nil, fmt.Errorf("response too short")
	}

	body := response[9:]
	if len(body) < 2 {
		return nil, fmt.Errorf("multimap body too short")
	}

	multimap := make(map[string][]string)
	offset := 0

	// Read number of entries
	numEntries := binary.BigEndian.Uint16(body[offset : offset+2])
	offset += 2

	// Parse each key-value pair
	for i := 0; i < int(numEntries); i++ {
		// Parse key
		key, newOffset, err := parseString(body, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key %d: %w", i, err)
		}
		offset = newOffset

		// Parse value list
		values, newOffset, err := parseStringList(body, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to parse values for key %s: %w", key, err)
		}
		offset = newOffset

		multimap[key] = values
	}

	return multimap, nil
}

// extractCassandraVersion determines Cassandra version from SUPPORTED multimap markers.
//
// Detection flow (priority order):
//  1. CQL_VERSION (primary, HIGH confidence)
//  2. PROTOCOL_VERSIONS (secondary, MEDIUM confidence)
//  3. COMPRESSION (tertiary, HIGH confidence for zstd=4.0+)
//
// Parameters:
//   - multimap: Parsed SUPPORTED multimap
//
// Returns:
//   - cassandraMetadata: Version, product, confidence, raw markers
func extractCassandraVersion(multimap map[string][]string) cassandraMetadata {
	metadata := cassandraMetadata{
		Product:          "Apache Cassandra", // Default
		Confidence:       "low",
		CQLVersion:       "",
		ProtocolVersions: []string{},
		Compression:      []string{},
	}

	// Check for ScyllaDB or DSE markers
	for key := range multimap {
		if strings.HasPrefix(key, "SCYLLA_") {
			metadata.Product = "ScyllaDB"
		} else if strings.HasPrefix(key, "DSE_") {
			metadata.Product = "DataStax Enterprise"
		}
	}

	// Extract CQL_VERSION (primary marker)
	if cqlVersions, ok := multimap["CQL_VERSION"]; ok && len(cqlVersions) > 0 {
		metadata.CQLVersion = cqlVersions[0]

		// Map CQL version to Cassandra version
		switch metadata.CQLVersion {
		case "3.4.7":
			metadata.Version = "5.0"
			metadata.Confidence = "high"
		case "3.4.6":
			metadata.Version = "4.1"
			metadata.Confidence = "high"
		case "3.4.5":
			metadata.Version = "4.0"
			metadata.Confidence = "high"
		case "3.4.4":
			metadata.Version = "3.11"
			metadata.Confidence = "high"
		default:
			// Parse major.minor pattern for fallback
			if strings.HasPrefix(metadata.CQLVersion, "3.4.") {
				metadata.Version = "3.*"
				metadata.Confidence = "medium"
			} else if strings.HasPrefix(metadata.CQLVersion, "3.3.") {
				metadata.Version = "2.2"
				metadata.Confidence = "medium"
			} else if strings.HasPrefix(metadata.CQLVersion, "3.2.") {
				metadata.Version = "2.1"
				metadata.Confidence = "medium"
			}
		}
	}

	// Extract PROTOCOL_VERSIONS (secondary marker, fallback)
	if protocolVersions, ok := multimap["PROTOCOL_VERSIONS"]; ok {
		metadata.ProtocolVersions = protocolVersions

		// Fallback version detection if CQL_VERSION didn't work
		if metadata.Version == "" {
			hasV6 := false
			hasV5 := false
			hasV4 := false
			hasV3 := false

			for _, pv := range protocolVersions {
				if strings.Contains(pv, "6/v6") {
					hasV6 = true
				} else if strings.Contains(pv, "5/v5") {
					hasV5 = true
				} else if strings.Contains(pv, "4/v4") {
					hasV4 = true
				} else if strings.Contains(pv, "3/v3") {
					hasV3 = true
				}
			}

			if hasV6 {
				metadata.Version = "5.0+"
				metadata.Confidence = "high"
			} else if hasV5 {
				metadata.Version = "4.0+"
				metadata.Confidence = "medium"
			} else if hasV4 && !hasV5 {
				metadata.Version = "2.2-3.x"
				metadata.Confidence = "medium"
			} else if hasV3 && !hasV4 {
				metadata.Version = "2.1.x"
				metadata.Confidence = "medium"
			}
		}
	}

	// Extract COMPRESSION (tertiary marker, refines version)
	if compression, ok := multimap["COMPRESSION"]; ok {
		metadata.Compression = compression

		// Zstd is HIGH confidence marker for Cassandra 4.0+
		hasZstd := false
		for _, comp := range compression {
			if strings.EqualFold(comp, "zstd") {
				hasZstd = true
				break
			}
		}

		if hasZstd {
			// If version unknown or claims < 4.0, but has zstd, trust zstd
			if metadata.Version == "" || metadata.Version == "*" {
				metadata.Version = "4.0+"
				metadata.Confidence = "high"
			}
		}
	}

	return metadata
}

// buildCassandraCPE generates CPE string for vulnerability tracking.
//
// CPE format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
// Uses wildcard (*) for unknown version (matches MongoDB/FTP/MySQL pattern).
//
// Parameters:
//   - product: "Apache Cassandra", "ScyllaDB", "DataStax Enterprise"
//   - version: Version string (e.g., "4.0") or empty for unknown
//
// Returns:
//   - string: CPE identifier
func buildCassandraCPE(product, version string) string {
	// CPE templates by product
	cpeTemplates := map[string]string{
		"Apache Cassandra":      "cpe:2.3:a:apache:cassandra:%s:*:*:*:*:*:*:*",
		"ScyllaDB":              "cpe:2.3:a:scylladb:scylla:%s:*:*:*:*:*:*:*",
		"DataStax Enterprise":   "cpe:2.3:a:datastax:datastax_enterprise:%s:*:*:*:*:*:*:*",
	}

	// Default to Apache Cassandra if product unknown
	if product == "" {
		product = "Apache Cassandra"
	}

	// Use wildcard for unknown version (matches MongoDB/FTP/RMI pattern)
	if version == "" {
		version = "*"
	}

	cpeTemplate, exists := cpeTemplates[product]
	if !exists {
		// Fallback to Apache Cassandra template
		cpeTemplate = cpeTemplates["Apache Cassandra"]
	}

	return fmt.Sprintf(cpeTemplate, version)
}

// DetectCassandra performs Cassandra fingerprinting using CQL OPTIONS/SUPPORTED handshake.
//
// Detection Strategy:
//  1. DETECTION PHASE: Send OPTIONS, validate SUPPORTED response structure
//  2. ENRICHMENT PHASE: Parse multimap, extract version markers, build CPE
//
// Parameters:
//   - conn: Network connection to Cassandra server
//   - timeout: Timeout for network operations
//
// Returns:
//   - cassandraMetadata: Enriched metadata (version, product, CPE)
//   - bool: true if Cassandra detected
//   - error: Error details if detection failed
func DetectCassandra(conn net.Conn, timeout time.Duration) (cassandraMetadata, bool, error) {
	// PHASE 1: Send OPTIONS frame
	optionsFrame := buildOPTIONSFrame()

	response, err := utils.SendRecv(conn, optionsFrame, timeout)
	if err != nil {
		return cassandraMetadata{}, false, err
	}

	if len(response) == 0 {
		return cassandraMetadata{}, false, &utils.ServerNotEnable{}
	}

	// PHASE 2: Validate SUPPORTED response
	isValid, err := isCassandraSUPPORTED(response, 0)
	if !isValid {
		return cassandraMetadata{}, false, err
	}

	// PHASE 3: Parse SUPPORTED multimap
	multimap, err := parseSUPPORTEDMultimap(response)
	if err != nil {
		// Cassandra detected (frame valid), but multimap parsing failed
		// Return minimal metadata
		return cassandraMetadata{
			Product:    "Apache Cassandra",
			Version:    "",
			Confidence: "low",
		}, true, nil
	}

	// PHASE 4: Extract version markers
	metadata := extractCassandraVersion(multimap)

	return metadata, true, nil
}

// Run implements the Plugin interface for Cassandra fingerprinting.
//
// Returns:
//   - *plugins.Service: Service metadata with CPE, or nil if not Cassandra
//   - error: Error details, or nil
func (p *CassandraPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	metadata, detected, err := DetectCassandra(conn, timeout)

	if !detected {
		return nil, err
	}

	// Build CPE (always generate, uses "*" for unknown version)
	cpe := buildCassandraCPE(metadata.Product, metadata.Version)

	// Create service payload
	payload := plugins.ServiceCassandra{
		Product:          metadata.Product,
		CQLVersion:       metadata.CQLVersion,
		ProtocolVersions: metadata.ProtocolVersions,
		Compression:      metadata.Compression,
		Confidence:       metadata.Confidence,
		CPEs:             []string{cpe},
	}

	return plugins.CreateServiceFrom(target, payload, false, metadata.Version, plugins.TCP), nil
}

// PortPriority returns true if the port is the default Cassandra CQL port (9042).
func (p *CassandraPlugin) PortPriority(port uint16) bool {
	return port == 9042
}

// Name returns the protocol name.
func (p *CassandraPlugin) Name() string {
	return CASSANDRA
}

// Type returns the protocol type (TCP).
func (p *CassandraPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the plugin execution priority.
// 100 = standard priority (run after high-priority protocols like SSH, before HTTP)
func (p *CassandraPlugin) Priority() int {
	return 100
}
