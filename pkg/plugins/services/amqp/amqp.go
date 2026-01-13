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
Package amqp implements fingerprinting for AMQP 0-9-1 message queue servers.

AMQP 0-9-1 Wire Protocol Detection

This plugin implements AMQP 0-9-1 fingerprinting for message queue brokers
like RabbitMQ, Apache Qpid, and other AMQP-compliant servers.

Detection Strategy:
  PHASE 1 - DETECTION (determines if the service is AMQP 0-9-1):
    PRIMARY PATH: Protocol header + Connection.Start handshake
      - Send: AMQP\x00\x00\x09\x01 (8-byte protocol header)
      - Expected: Connection.Start method frame (class=10, method=10)
      - Works on ALL AMQP 0-9-1 brokers
      - Directly provides server properties (100% confidence)

  PHASE 2 - ENRICHMENT (extracts version and metadata):
    After AMQP is detected, parse server-properties FieldTable:
      - product: Broker name (RabbitMQ, Qpid, etc.)
      - version: Broker version (e.g., "3.13.0")
      - platform: Runtime platform (e.g., "Erlang/OTP 26.2.1")

AMQP 0-9-1 Protocol:

Protocol Header:
  Client → Server: AMQP\x00\x00\x09\x01 (8 bytes)
    - Bytes 0-3: ASCII "AMQP" (0x41 0x4D 0x51 0x50)
    - Byte 4: Protocol ID (0x00 for AMQP)
    - Byte 5: Protocol ID Major (0x00)
    - Byte 6: Protocol Major Version (0x09 = version 0)
    - Byte 7: Protocol Minor Version (0x01 = version 9-1)

Connection.Start Frame:
  Server → Client: Method Frame (type=0x01)
    Frame Structure:
      [Frame Type][Channel][Payload Size][Payload][Frame End]
         1 byte    2 bytes    4 bytes      N bytes   1 byte (0xCE)

    Payload Structure:
      [Class ID][Method ID][version-major][version-minor][server-properties][mechanisms][locales]
       2 bytes   2 bytes    1 byte         1 byte         FieldTable         longstr     longstr

    Server Properties FieldTable:
      - product: "RabbitMQ" | "Qpid" | etc.
      - version: "3.13.0" | etc.
      - platform: "Erlang/OTP 26.2.1" | etc.
      - copyright, information, capabilities (optional)

Frame Types:
  - 0x01 - Method Frame (commands like Connection.Start)
  - 0x02 - Content Header Frame
  - 0x03 - Content Body Frame
  - 0x04 - Heartbeat Frame

Frame End Marker:
  - Always 0xCE (validates frame integrity)

Version Compatibility:
  - AMQP 0-9-1 is the most widely deployed version (RabbitMQ, etc.)
  - AMQP 1.0 uses a different protocol header (not compatible)
  - This plugin only detects AMQP 0-9-1

Note: The Connection.Start frame is sent immediately after the protocol header,
before any authentication, making detection possible without credentials.
*/
package amqp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type AMQPPlugin struct{}

const AMQP = "amqp"

// AMQP default port
const DEFAULT_PORT = 5672

// AMQP 0-9-1 protocol constants
const (
	FRAME_METHOD    = 0x01
	FRAME_END       = 0xCE
	CLASS_CONNECTION = 10
	METHOD_START    = 10
)

func init() {
	plugins.RegisterPlugin(&AMQPPlugin{})
}

// checkAMQPProtocolHeader validates the AMQP 0-9-1 protocol header.
//
// Expected format: "AMQP\x00\x00\x09\x01" (8 bytes)
//
// Parameters:
//   - header: The protocol header bytes
//
// Returns:
//   - error: nil if valid, error details if validation fails
func checkAMQPProtocolHeader(header []byte) error {
	// AMQP protocol header must be exactly 8 bytes
	if len(header) != 8 {
		return &utils.InvalidResponseErrorInfo{
			Service: AMQP,
			Info:    "header too short",
		}
	}

	// Check magic bytes "AMQP"
	if !bytes.Equal(header[0:4], []byte{'A', 'M', 'Q', 'P'}) {
		return &utils.InvalidResponseErrorInfo{
			Service: AMQP,
			Info:    "invalid AMQP magic bytes",
		}
	}

	// Check AMQP 0-9-1 version bytes
	// Byte 4: Protocol ID (0x00)
	// Byte 5: Protocol ID Major (0x00)
	// Byte 6: Protocol Major Version (0x09)
	// Byte 7: Protocol Minor Version (0x01)
	if header[4] != 0x00 || header[5] != 0x00 || header[6] != 0x09 || header[7] != 0x01 {
		return &utils.InvalidResponseErrorInfo{
			Service: AMQP,
			Info:    "not AMQP 0-9-1",
		}
	}

	return nil
}

// parseConnectionStart parses an AMQP Connection.Start method frame.
//
// Frame Structure:
//   [Frame Type][Channel][Payload Size][Payload][Frame End]
//      1 byte    2 bytes    4 bytes      N bytes   1 byte
//
// Payload Structure:
//   [Class ID][Method ID][version-major][version-minor][server-properties][mechanisms][locales]
//    2 bytes   2 bytes    1 byte         1 byte         FieldTable         longstr     longstr
//
// Parameters:
//   - frame: The complete frame bytes
//
// Returns:
//   - map[string]interface{}: Server properties from FieldTable
//   - error: nil if valid, error details if validation fails
func parseConnectionStart(frame []byte) (map[string]interface{}, error) {
	// Minimum frame size: 1 (type) + 2 (channel) + 4 (size) + 4 (class+method) + 2 (versions) + 1 (end) = 14 bytes
	if len(frame) < 14 {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: AMQP,
			Info:    "frame too short",
		}
	}

	// Parse frame header
	frameType := frame[0]
	channel := binary.BigEndian.Uint16(frame[1:3])
	payloadSize := binary.BigEndian.Uint32(frame[3:7])

	// Validate frame type (must be Method Frame)
	if frameType != FRAME_METHOD {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: AMQP,
			Info:    "not a method frame",
		}
	}

	// Validate channel (must be 0 for connection-level methods)
	if channel != 0 {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: AMQP,
			Info:    "not on channel 0",
		}
	}

	// Validate frame size
	expectedFrameSize := 7 + int(payloadSize) + 1 // header + payload + frame-end
	if len(frame) < expectedFrameSize {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: AMQP,
			Info:    "incomplete frame",
		}
	}

	// Validate frame end marker
	frameEnd := frame[expectedFrameSize-1]
	if frameEnd != FRAME_END {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: AMQP,
			Info:    "invalid frame end marker",
		}
	}

	// Parse payload
	payload := frame[7 : 7+payloadSize]
	if len(payload) < 6 { // class + method + version-major + version-minor
		return nil, &utils.InvalidResponseErrorInfo{
			Service: AMQP,
			Info:    "payload too short",
		}
	}

	classID := binary.BigEndian.Uint16(payload[0:2])
	methodID := binary.BigEndian.Uint16(payload[2:4])

	// Validate Connection.Start (class=10, method=10)
	if classID != CLASS_CONNECTION || methodID != METHOD_START {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: AMQP,
			Info:    "not Connection.Start",
		}
	}

	// Parse version fields (we don't use these, but skip them)
	// version-major: payload[4]
	// version-minor: payload[5]

	// Parse server-properties FieldTable
	if len(payload) < 10 { // need at least 4 bytes for FieldTable length
		return nil, &utils.InvalidResponseErrorInfo{
			Service: AMQP,
			Info:    "missing server-properties",
		}
	}

	fieldTableSize := binary.BigEndian.Uint32(payload[6:10])
	if len(payload) < 10+int(fieldTableSize) {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: AMQP,
			Info:    "incomplete server-properties",
		}
	}

	fieldTableData := payload[10 : 10+fieldTableSize]

	// Parse FieldTable
	properties, err := parseFieldTable(fieldTableData)
	if err != nil {
		return nil, err
	}

	return properties, nil
}

// parseFieldTable parses an AMQP FieldTable structure.
//
// FieldTable format:
//   For each field:
//     [name-length][name][type][value]
//      1 byte       N bytes 1 byte varies
//
// Supported types:
//   - 'S': longstr (4-byte length + string)
//   - 't': boolean (1 byte)
//   - 'I': long-int (4 bytes)
//   - 'F': FieldTable (nested)
//
// Parameters:
//   - data: The FieldTable bytes
//
// Returns:
//   - map[string]interface{}: Parsed fields
//   - error: Parsing error if any
func parseFieldTable(data []byte) (map[string]interface{}, error) {
	fields := make(map[string]interface{})
	offset := 0

	for offset < len(data) {
		// Read field name length (1 byte)
		if offset+1 > len(data) {
			break
		}
		nameLen := int(data[offset])
		offset++

		// Read field name
		if offset+nameLen > len(data) {
			break
		}
		name := string(data[offset : offset+nameLen])
		offset += nameLen

		// Read field type (1 byte)
		if offset+1 > len(data) {
			break
		}
		fieldType := data[offset]
		offset++

		// Parse field value based on type
		switch fieldType {
		case 'S': // longstr (4-byte length + string)
			if offset+4 > len(data) {
				break
			}
			strLen := binary.BigEndian.Uint32(data[offset : offset+4])
			offset += 4

			if offset+int(strLen) > len(data) {
				break
			}
			value := string(data[offset : offset+int(strLen)])
			offset += int(strLen)

			fields[name] = value

		case 't': // boolean (1 byte)
			if offset+1 > len(data) {
				break
			}
			fields[name] = data[offset] != 0
			offset++

		case 'I': // long-int (4 bytes, signed)
			if offset+4 > len(data) {
				break
			}
			fields[name] = int32(binary.BigEndian.Uint32(data[offset : offset+4]))
			offset += 4

		case 'F': // FieldTable (nested, 4-byte length + data)
			if offset+4 > len(data) {
				break
			}
			tableLen := binary.BigEndian.Uint32(data[offset : offset+4])
			offset += 4

			if offset+int(tableLen) > len(data) {
				break
			}
			nestedData := data[offset : offset+int(tableLen)]
			nestedFields, _ := parseFieldTable(nestedData)
			fields[name] = nestedFields
			offset += int(tableLen)

		default:
			// Unknown type, skip this field (can't determine length reliably)
			// This is safe because we only care about string fields anyway
			break
		}
	}

	return fields, nil
}

// extractStringField extracts a string value from the properties map.
//
// Parameters:
//   - properties: The server properties map
//   - key: The field key to extract
//
// Returns:
//   - string: The field value, or empty string if not found
func extractStringField(properties map[string]interface{}, key string) string {
	if val, ok := properties[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return ""
}

// buildAMQPCPE constructs a CPE (Common Platform Enumeration) string for AMQP.
// CPE format: cpe:2.3:a:rabbitmq:rabbitmq:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" wildcard to match fingerprintx pattern
// and enable asset inventory use cases even without precise version information.
//
// Parameters:
//   - version: Broker version string (e.g., "3.13.0"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" wildcard
func buildAMQPCPE(version string) string {
	// Use wildcard for unknown versions (matches fingerprintx pattern)
	if version == "" {
		version = "*"
	}

	// RabbitMQ CPE template: cpe:2.3:a:rabbitmq:rabbitmq:{version}:*:*:*:*:*:*:*
	return fmt.Sprintf("cpe:2.3:a:rabbitmq:rabbitmq:%s:*:*:*:*:*:*:*", version)
}

// DetectAMQP performs AMQP 0-9-1 fingerprinting using the protocol handshake.
//
// Detection Strategy:
//  1. DETECTION PHASE: Send AMQP protocol header and receive Connection.Start
//     - Send protocol header: AMQP\x00\x00\x09\x01
//     - Receive Connection.Start method frame
//     - Parse server-properties FieldTable
//  2. ENRICHMENT PHASE: Extract product, version, and platform from server-properties
//
// Parameters:
//   - conn: Network connection to the AMQP server
//   - timeout: Timeout duration for network operations
//
// Returns:
//   - string: Version string if detected, empty string otherwise
//   - map[string]interface{}: Server properties (product, version, platform)
//   - bool: true if this appears to be AMQP
//   - error: Error details if detection failed
func DetectAMQP(conn net.Conn, timeout time.Duration) (string, map[string]interface{}, bool, error) {
	// PHASE 1: Send AMQP 0-9-1 protocol header
	protocolHeader := []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}

	// Validate our own protocol header (sanity check)
	if err := checkAMQPProtocolHeader(protocolHeader); err != nil {
		return "", nil, false, err
	}

	// Send protocol header
	response, err := utils.SendRecv(conn, protocolHeader, timeout)
	if err != nil {
		return "", nil, false, err
	}
	if len(response) == 0 {
		return "", nil, false, &utils.ServerNotEnable{}
	}

	// PHASE 2: Parse Connection.Start frame
	properties, err := parseConnectionStart(response)
	if err != nil {
		return "", nil, false, err
	}

	// PHASE 3: Extract server properties
	product := extractStringField(properties, "product")
	version := extractStringField(properties, "version")
	platform := extractStringField(properties, "platform")

	// Build metadata map
	metadata := map[string]interface{}{
		"product": product,
		"version": version,
	}
	if platform != "" {
		metadata["platform"] = platform
	}

	return version, metadata, true, nil
}

func (p *AMQPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	version, metadata, detected, err := DetectAMQP(conn, timeout)
	if !detected {
		return nil, err
	}

	// AMQP detected! Build service response
	payload := plugins.ServiceAMQP{
		Product:  extractStringField(metadata, "product"),
		Version:  version,
		Platform: extractStringField(metadata, "platform"),
	}

	// Always generate CPE - uses "*" for unknown version (matches fingerprintx pattern)
	cpe := buildAMQPCPE(version)
	payload.CPEs = []string{cpe}

	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *AMQPPlugin) PortPriority(port uint16) bool {
	return port == DEFAULT_PORT
}

func (p *AMQPPlugin) Name() string {
	return AMQP
}

func (p *AMQPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *AMQPPlugin) Priority() int {
	// Priority 50: Binary protocol, run before generic HTTP probes
	return 50
}
