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
Package firebird implements Firebird SQL database server fingerprinting.

Firebird Detection Strategy:

The plugin detects Firebird SQL servers by sending an op_connect packet and
analyzing the server's response. The wire protocol handshake provides reliable
detection through protocol version negotiation.

Wire Protocol Overview:

Firebird uses a binary wire protocol over TCP (default port 3050). The client
initiates connection with an op_connect packet offering supported protocol
versions. The server responds with one of:

  - op_accept (3): Connection accepted, protocol negotiated
  - op_cond_accept (20): Conditional acceptance (protocol 13+, auth required)
  - op_accept_data (21): Acceptance with authentication data (protocol 13+)
  - op_reject (4): Server cannot fulfill protocol requirements
  - op_response (9): Error response with status vector

Protocol Version History:

  - Protocol 10: Firebird 1.x / InterBase (ambiguous, no 0x8000 flag)
  - Protocol 11: Firebird 2.1+ (0x800b = 0x8000 | 11)
  - Protocol 12: Firebird 2.5+ (0x800c)
  - Protocol 13: Firebird 3.0.0-3.0.1 (0x800d)
  - Protocol 15: Firebird 3.0.2+ (0x800f)
  - Protocol 16: Firebird 4.0+ (0x8010)
  - Protocol 17: Firebird 5.0+ (0x8011)

The FB_PROTOCOL_FLAG (0x8000) distinguishes Firebird from InterBase. Protocol
version 14 (without 0x8000) indicates InterBase, not Firebird.

Version Detection:

Phase 1 (Detection): Protocol version from op_accept response maps to major.minor
version with HIGH confidence.

Phase 2 (Enrichment - Optional): After database attachment, query isc_info_firebird_version
to extract precise patch version (e.g., "5.0.3"). Requires valid database path and
optional authentication.

InterBase Disambiguation:

Firebird and InterBase both use port 3050 but are distinguishable via protocol
version. Modern Firebird uses protocols 11-17 with 0x8000 flag. InterBase protocol
14 lacks this flag. Protocol 10 is ambiguous (both systems support it).
*/
package firebird

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

// FirebirdPlugin implements the Plugin interface for Firebird SQL server fingerprinting
type FirebirdPlugin struct{}

const (
	FIREBIRD = "firebird"

	// Protocol operation codes
	opConnect     = 1  // Client initiates connection
	opAccept      = 3  // Server accepts connection
	opReject      = 4  // Server rejects connection (but confirms Firebird presence)
	opResponse    = 9  // Error response with status vector
	opCondAccept  = 20 // Conditional acceptance (protocol 13+)
	opAcceptData  = 21 // Acceptance with authentication data (protocol 13+)
	opAttach      = 2  // Attach to database operation

	// Protocol version constants
	// FB_PROTOCOL_FLAG (0x8000) distinguishes Firebird from InterBase
	fbProtocolFlag = 0x8000

	// Connect version and architecture
	connectVersion3 = 3 // CONNECT_VERSION3
	archGeneric     = 1 // Architecture type (generic)
)

func init() {
	plugins.RegisterPlugin(&FirebirdPlugin{})
}

// Run performs Firebird server fingerprinting through two phases:
// Phase 1 (Detection): Send op_connect, receive op_accept, extract protocol version
// Phase 2 (Enrichment): Map protocol to major.minor version (HIGH confidence)
func (p *FirebirdPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Phase 1: Detection - Send op_connect packet
	connectPacket := buildConnectPacket()

	response, err := utils.SendRecv(conn, connectPacket, timeout)
	if err != nil {
		return nil, err
	}

	if len(response) < 4 {
		return nil, nil // Not Firebird (response too short)
	}

	// Parse response opcode
	opcode := binary.BigEndian.Uint32(response[0:4])

	// Check for Firebird acceptance responses
	switch opcode {
	case opAccept, opCondAccept, opAcceptData:
		// Need at least 16 bytes for full op_accept response
		if len(response) < 16 {
			return nil, &utils.InvalidResponseErrorInfo{
				Service: FIREBIRD,
				Info:    "op_accept response truncated (< 16 bytes)",
			}
		}

		// Extract protocol version from bytes 4-7
		protocolVersion := int32(binary.BigEndian.Uint32(response[4:8]))

		// Verify this is Firebird (not InterBase)
		isFirebird, version := identifyFirebird(protocolVersion)
		if !isFirebird {
			return nil, nil // Not Firebird (likely InterBase or unknown)
		}

		// Generate CPE with version from protocol mapping
		cpe := buildFirebirdCPE(version)

		payload := plugins.ServiceFirebird{
			ProtocolVersion: protocolVersion,
			CPEs:            []string{cpe},
		}

		return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil

	case opReject:
		// Server rejected connection but responded (still confirms Firebird)
		// Cannot extract protocol version from rejection, use wildcard CPE
		cpe := buildFirebirdCPE("")

		payload := plugins.ServiceFirebird{
			CPEs: []string{cpe},
		}

		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil

	case opResponse:
		// Error response - server understands protocol but returned error
		// Could be Firebird, check status vector
		// For now, treat as not detected (avoid false positives)
		return nil, nil

	default:
		// Unknown opcode, not Firebird
		return nil, nil
	}
}

// PortPriority returns true if the port is Firebird's default port 3050
func (p *FirebirdPlugin) PortPriority(port uint16) bool {
	return port == 3050
}

// Name returns the protocol name
func (p *FirebirdPlugin) Name() string {
	return FIREBIRD
}

// Type returns the protocol type (TCP)
func (p *FirebirdPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the execution priority (default 100)
func (p *FirebirdPlugin) Priority() int {
	return 100
}

// buildConnectPacket constructs an op_connect packet offering protocols 10, 13, 16, 17
//
// Packet structure:
//
//	p_operation: op_connect (1)
//	p_cnct_operation: op_attach (2)
//	p_cnct_cversion: CONNECT_VERSION3 (3)
//	p_cnct_client: arch_generic (1)
//	p_cnct_file: "" (empty database path for fingerprinting)
//	p_cnct_count: 4 (number of protocols offered)
//	p_cnct_user_id: [] (empty UID buffer for fingerprinting)
//	--- For each protocol (repeated 4 times) ---
//	p_cnct_version: protocol version (10, 13, 16, 17)
//	p_cnct_architecture: arch_generic (1)
//	p_cnct_min_type: 0
//	p_cnct_max_type: 5
//	p_cnct_weight: preference weight (2, 4, 6, 8)
func buildConnectPacket() []byte {
	var buf []byte

	// Header
	buf = append(buf, packInt(opConnect)...)
	buf = append(buf, packInt(opAttach)...)
	buf = append(buf, packInt(connectVersion3)...)
	buf = append(buf, packInt(archGeneric)...)
	buf = append(buf, packString("")...) // Empty database path

	// Offer 4 protocol versions (10, 13, 16, 17)
	buf = append(buf, packInt(4)...)
	buf = append(buf, packString("")...) // Empty UID buffer for fingerprinting

	// Protocol 10 (legacy, for maximum compatibility and InterBase detection)
	buf = append(buf, packInt(0x0000000a)...)  // version 10 (no 0x8000 flag)
	buf = append(buf, packInt(archGeneric)...) // architecture
	buf = append(buf, packInt(0)...)           // min_type
	buf = append(buf, packInt(5)...)           // max_type
	buf = append(buf, packInt(2)...)           // weight (lowest priority)

	// Protocol 13 (Firebird 3.0+)
	buf = append(buf, packInt(0x0000800d)...)  // version 13 (0x8000 | 13)
	buf = append(buf, packInt(archGeneric)...) // architecture
	buf = append(buf, packInt(0)...)           // min_type
	buf = append(buf, packInt(5)...)           // max_type
	buf = append(buf, packInt(4)...)           // weight

	// Protocol 16 (Firebird 4.0+)
	buf = append(buf, packInt(0x00008010)...)  // version 16 (0x8000 | 16)
	buf = append(buf, packInt(archGeneric)...) // architecture
	buf = append(buf, packInt(0)...)           // min_type
	buf = append(buf, packInt(5)...)           // max_type
	buf = append(buf, packInt(6)...)           // weight (higher priority)

	// Protocol 17 (Firebird 5.0+)
	buf = append(buf, packInt(0x00008011)...)  // version 17 (0x8000 | 17)
	buf = append(buf, packInt(archGeneric)...) // architecture
	buf = append(buf, packInt(0)...)           // min_type
	buf = append(buf, packInt(5)...)           // max_type
	buf = append(buf, packInt(8)...)           // weight (highest priority)

	return buf
}

// packInt packs an int32 value as big-endian 4-byte sequence
func packInt(value int32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(value))
	return buf
}

// packString packs a string as length-prefixed sequence (4-byte length + string bytes)
func packString(s string) []byte {
	length := len(s)
	buf := make([]byte, 4+length)
	binary.BigEndian.PutUint32(buf[0:4], uint32(length))
	copy(buf[4:], s)

	// Pad to 4-byte boundary
	padding := (4 - (length % 4)) % 4
	buf = append(buf, make([]byte, padding)...)

	return buf
}

// identifyFirebird determines if the protocol version indicates Firebird (vs InterBase)
// and maps the protocol version to a Firebird major.minor version string.
//
// Returns:
//   - isFirebird: true if this is Firebird (not InterBase)
//   - version: Firebird major.minor version string (e.g., "5.0", "4.0")
//
// Protocol Version Mapping:
//   - 17 (0x8011): Firebird 5.0
//   - 16 (0x8010): Firebird 4.0
//   - 15 (0x800f): Firebird 3.0.2+
//   - 13 (0x800d): Firebird 3.0
//   - 12 (0x800c): Firebird 2.5
//   - 11 (0x800b): Firebird 2.1
//   - 10 (0x000a): Firebird 1.x OR InterBase (ambiguous)
//   - 14 (0x000e): InterBase (NOT Firebird)
//
// The FB_PROTOCOL_FLAG (0x8000) distinguishes Firebird from InterBase for
// protocol versions 11+.
func identifyFirebird(protocolVersion int32) (isFirebird bool, version string) {
	// Protocol 14 (no 0x8000 flag) is InterBase-specific
	if protocolVersion == 14 {
		return false, "" // InterBase, not Firebird
	}

	// Protocol 10 is ambiguous (both Firebird 1.x and InterBase support it)
	// Modern Firebird servers default to protocols 13-17, so protocol 10
	// responses are rare. We'll accept it as low-confidence Firebird.
	if protocolVersion == 10 {
		return true, "" // Ambiguous, use wildcard CPE
	}

	// Protocols 11-17 should have FB_PROTOCOL_FLAG (0x8000)
	if protocolVersion > 10 && (protocolVersion&fbProtocolFlag) == 0 {
		return false, "" // Missing Firebird flag, not Firebird
	}

	// Extract bare protocol version (remove 0x8000 flag)
	bareVersion := protocolVersion & 0x7fff

	// Map protocol version to Firebird major.minor version
	switch bareVersion {
	case 17:
		return true, "5.0"
	case 16:
		return true, "4.0"
	case 15:
		return true, "3.0.2"
	case 13:
		return true, "3.0"
	case 12:
		return true, "2.5"
	case 11:
		return true, "2.1"
	default:
		// Unknown protocol version, but has Firebird flag
		return true, ""
	}
}

// buildFirebirdCPE generates a CPE (Common Platform Enumeration) string for Firebird.
//
// Uses wildcard version ("*") when version is unknown to match FTP/MySQL/PostgreSQL
// plugin behavior and enable asset inventory use cases even without precise version.
//
// CPE format: cpe:2.3:a:firebirdsql:firebird:{version}:*:*:*:*:*:*:*
//
// Parameters:
//   - version: Version string (e.g., "4.0", "5.0.3"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" wildcard
func buildFirebirdCPE(version string) string {
	// Use wildcard for unknown versions (matches FTP/MySQL/PostgreSQL pattern)
	if version == "" {
		version = "*"
	}

	// Format: cpe:2.3:a:firebirdsql:firebird:{version}:*:*:*:*:*:*:*
	return fmt.Sprintf("cpe:2.3:a:firebirdsql:firebird:%s:*:*:*:*:*:*:*", version)
}
