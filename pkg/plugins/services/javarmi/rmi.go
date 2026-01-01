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

// Package javarmi provides fingerprinting for Java RMI (Remote Method Invocation) services
// using the JRMP (Java Remote Method Protocol) wire protocol.
//
// Detection Strategy:
// Java RMI Registry services can be reliably detected via the JRMP handshake protocol,
// which uses a unique magic number 0x4a524d49 ("JRMI"). The protocol has remained stable
// since JDK 1.1, making it highly reliable for service detection.
//
// Version Detection Limitation:
// JRMP wire protocol does not encode JDK version information. The handshake is identical
// across all JDK versions (8, 11, 17, 21, etc.), making precise version detection
// technically infeasible without application-level probing. This plugin provides
// service detection only.
//
// Protocol Reference:
// - Official Spec: https://docs.oracle.com/javase/9/docs/specs/rmi/protocol.html
// - OpenJDK Source: src/java.rmi/share/classes/sun/rmi/transport/
package javarmi

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

// RMIPlugin implements the Plugin interface for Java RMI fingerprinting
type RMIPlugin struct{}

const RMI = "java-rmi"

// Common RMI ports
// Port 1099 is the standard RMI Registry port
var commonRMIPorts = map[int]struct{}{
	1098:  {}, // Alternative registry port
	1099:  {}, // Standard RMI Registry (most common)
	9999:  {}, // Common for JMX over RMI
	10000: {}, // Custom registry ports (range)
	10001: {},
	10099: {},
}

// JRMP Protocol Constants
// These values are defined in sun.rmi.transport.TransportConstants
const (
	// Magic number: 0x4a524d49 = "JRMI" in ASCII
	magicByte1 = 0x4a // 'J'
	magicByte2 = 0x52 // 'R'
	magicByte3 = 0x4d // 'M'
	magicByte4 = 0x49 // 'I'

	// Protocol version: 2 (used since JDK 1.1, despite spec showing version 1)
	versionByte1 = 0x00
	versionByte2 = 0x02

	// Protocol type: StreamProtocol (persistent connection)
	streamProtocol = 0x4b

	// Response codes
	protocolAck  = 0x4e // Server accepts protocol
	protocolNack = 0x4f // Server rejects protocol
)

func init() {
	plugins.RegisterPlugin(&RMIPlugin{})
}

// Run performs JRMP handshake to detect Java RMI services
//
// The method implements a two-phase detection:
// 1. Detection: Send JRMP handshake and perform 5-layer validation on response
// 2. Enrichment: Extract endpoint metadata from response
//
// The 5-layer validation approach provides high confidence detection while
// maintaining simplicity and performance (single network round-trip).
//
// Note: Version detection is not performed as JRMP protocol is version-agnostic.
// The handshake is identical across all JDK versions (8, 11, 17, 21, etc.).
func (p *RMIPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Phase 1: Detection via JRMP handshake with comprehensive validation
	detected, endpoint, err := detectRMI(conn, timeout)
	if err != nil {
		return nil, err
	}

	if !detected {
		return nil, nil // Not an RMI service
	}

	// Phase 2: Build service info
	// Note: CPE is generic because JRMP protocol does not encode JDK version
	// The handshake is identical across all JDK versions (7-21)
	info := &plugins.ServiceRMI{
		Endpoint: endpoint,
		CPEs: []string{
			"cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*",
		},
	}

	// Return detected service
	// Version is empty string because JDK version cannot be determined from JRMP handshake
	return plugins.CreateServiceFrom(target, info, false, "", plugins.TCP), nil
}

// detectRMI performs JRMP protocol handshake with multi-layer validation
//
// Detection Strategy:
// Sends single JRMP handshake and performs 5-layer validation on the response
// to eliminate false positives from random data. This validation is more
// comprehensive than nmap's current RMI detection.
//
// Validation Layers:
// 1. Minimum length check (≥3 bytes for ProtocolAck + length field)
// 2. ProtocolAck byte validation (must be exactly 0x4E)
// 3. Endpoint length sanity check (3-253 bytes for valid hostname/IP)
// 4. Response length consistency (actual length ≥ claimed structure)
// 5. ASCII validation (endpoint must be printable characters)
//
// Handshake format (7 bytes):
//
//	[4 bytes] Magic:   0x4a 0x52 0x4d 0x49 ("JRMI")
//	[2 bytes] Version: 0x00 0x02
//	[1 byte]  Protocol: 0x4b (StreamProtocol)
//
// Expected response format:
//
//	[1 byte]  Response: 0x4e (ProtocolAck)
//	[2 bytes] Length: String length (big-endian uint16) for endpoint
//	[N bytes] Host: Hostname or IP address
//	[2 bytes] Port: Port number (big-endian uint16)
//	[...] Additional endpoint data
//
// Returns:
//   - detected: true if response passes all 5 validation layers
//   - endpoint: extracted endpoint information from response
//   - error: network or protocol errors
func detectRMI(conn net.Conn, timeout time.Duration) (bool, string, error) {
	// Build JRMP handshake
	handshake := []byte{
		magicByte1,     // 0x4a = 'J'
		magicByte2,     // 0x52 = 'R'
		magicByte3,     // 0x4d = 'M'
		magicByte4,     // 0x49 = 'I'
		versionByte1,   // 0x00
		versionByte2,   // 0x02
		streamProtocol, // 0x4b
	}

	// Send handshake and receive response
	response, err := utils.SendRecv(conn, handshake, timeout)
	if err != nil {
		return false, "", err
	}

	// Perform 5-layer validation to eliminate false positives
	// This is more comprehensive than nmap's validation
	if !isValidRMIResponse(response) {
		return false, "", nil
	}

	// RMI detected - extract endpoint information
	endpoint := extractEndpoint(response[1:])

	return true, endpoint, nil
}

// isValidRMIResponse validates that the response matches JRMP protocol structure
//
// Validation checks (multi-layer defense against false positives):
// 1. Minimum length check (must have ProtocolAck + length field)
// 2. ProtocolAck byte validation (0x4E)
// 3. Endpoint length field validation (must be reasonable)
// 4. Response length consistency (actual length >= claimed length)
//
// Returns true only if ALL validation checks pass
func isValidRMIResponse(response []byte) bool {
	// Check 1: Minimum response length
	// Must have: [1 byte ProtocolAck][2 bytes length][at least some data]
	if len(response) < 3 {
		return false
	}

	// Check 2: First byte must be ProtocolAck
	if response[0] != protocolAck {
		// Explicitly reject ProtocolNack to avoid false positives
		// (even though 0x4F is valid JRMP, we want strict matching)
		return false
	}

	// Check 3: Validate endpoint length field (prevents random data false positives)
	// Extract claimed string length from bytes 1-2
	claimedLength := binary.BigEndian.Uint16(response[1:3])

	// Sanity check: endpoint hostname/IP should be reasonable length
	// Too short (< 3): Invalid (e.g., "a.b" minimum for IP)
	// Too long (> 253): Invalid (DNS max hostname length is 253)
	if claimedLength < 3 || claimedLength > 253 {
		return false
	}

	// Check 4: Verify actual response length matches structure
	// Minimum required: 1 (ack) + 2 (length) + claimedLength (host) + 2 (nulls) + 2 (port)
	// Note: Using >= not == because JRMP spec allows "Additional endpoint data (variable)"
	// after the port field. Different RMI implementations may include extra metadata.
	requiredLength := 1 + 2 + int(claimedLength) + 2 + 2 // +2 for null bytes, +2 for port
	if len(response) < requiredLength {
		return false
	}

	// Check 5: Validate endpoint data looks like hostname/IP (printable ASCII)
	// Extract the claimed hostname bytes
	endpointStart := 3
	endpointEnd := 3 + int(claimedLength)
	endpointBytes := response[endpointStart:endpointEnd]

	// Endpoint should contain only printable ASCII characters
	// (hostnames/IPs are ASCII: a-z, A-Z, 0-9, '.', '-', ':')
	for _, b := range endpointBytes {
		// Allow printable ASCII range (space to tilde) plus common hostname chars
		if b < 32 || b > 126 {
			return false
		}
	}

	// All validation checks passed - high confidence this is RMI
	return true
}

// extractEndpoint parses the endpoint information from JRMP handshake response
//
// Endpoint format (from JRMP spec):
//
//	[2 bytes] Length: String length (big-endian uint16)
//	[N bytes] Host:   Hostname or IP address (UTF-8 string)
//	[2 bytes] Nulls:  0x00 0x00 (padding/separator)
//	[2 bytes] Port:   Port number (big-endian uint16)
//
// Example response:
//
//	4e 00 0a 31 37 32 2e 31 38 2e 30 2e 31 00 00 fc 64
//	^^ ACK
//	   ^^^^^ Length: 10
//	        ^^^^^^^^^^^^^^^^^^^^^^^ "172.18.0.1"
//	                                 ^^^^^ Nulls: 0x00 0x00
//	                                       ^^^^^ Port: 0xFC64 = 64612
//
// Returns a human-readable endpoint string (e.g., "172.18.0.1:64612"), or just
// the hostname if port cannot be parsed
func extractEndpoint(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	// Read string length (big-endian uint16)
	strLen := binary.BigEndian.Uint16(data[0:2])
	if len(data) < int(2+strLen) {
		return ""
	}

	// Extract host string
	host := string(data[2 : 2+strLen])

	// After the host string, there are 2 null bytes, then 2-byte port
	// Total offset: 2 (length) + strLen (host) + 2 (nulls) + 2 (port)
	portOffset := 2 + int(strLen) + 2 // +2 for the null bytes
	if len(data) >= portOffset+2 {
		port := binary.BigEndian.Uint16(data[portOffset : portOffset+2])
		if port > 0 {
			// Return "host:port" format
			return fmt.Sprintf("%s:%d", host, port)
		}
	}

	// Return just host if port not available
	return host
}

// PortPriority returns true if the port is commonly used for RMI services
//
// Standard RMI Registry port is 1099. Other common ports include:
// - 1098: Alternative registry
// - 9999: JMX over RMI
// - 10000-10099: Custom registry configurations
func (p *RMIPlugin) PortPriority(port uint16) bool {
	_, ok := commonRMIPorts[int(port)]
	return ok
}

// Name returns the protocol identifier for this plugin
func (p *RMIPlugin) Name() string {
	return RMI
}

// Type returns TCP as RMI uses TCP transport
func (p *RMIPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the execution priority for this plugin
//
// Returns 500 (medium priority) as RMI should run after protocol-specific
// checks but before generic HTTP probes
func (p *RMIPlugin) Priority() int {
	return 500
}
