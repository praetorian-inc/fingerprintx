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
Neo4j Bolt Protocol Fingerprinting

This plugin implements Neo4j fingerprinting using the Bolt protocol, Neo4j's
binary protocol for database communication.

Detection Strategy:
  PHASE 1 - Detection (determines if the service is Bolt):
    - Send Bolt magic bytes (60 60 B0 17) followed by version proposals
    - If server responds with a non-zero 4-byte version number, it's a Bolt server
    - If server responds with zeros or closes connection, it's not Bolt

  PHASE 2 - Enrichment (extracts version and identifies Neo4j specifically):
    - After successful handshake, send HELLO message
    - Parse SUCCESS response for "server" field (e.g., "Neo4j/5.13.0")
    - Verify "Neo4j/" prefix to distinguish from other Bolt implementations (TuGraph, etc.)
    - Extract version number and generate CPE

Bolt Protocol Wire Format:

Handshake (20 bytes total):
  Magic:    60 60 B0 17         (4 bytes - identifies Bolt connection)
  Version1: 00 00 VV VV         (4 bytes - preferred version, big-endian)
  Version2: 00 00 VV VV         (4 bytes - fallback version)
  Version3: 00 00 VV VV         (4 bytes - fallback version)
  Version4: 00 00 VV VV         (4 bytes - fallback version)

Server Response (4 bytes):
  Version:  00 00 VV VV         (Selected version, or 00 00 00 00 if no match)

Message Chunking:
  Each message after handshake is chunked:
  [2-byte length (big-endian)] [chunk data] ... [00 00 terminator]

HELLO Message Structure (PackStream encoded):
  B1 01                         Structure with 1 field, tag HELLO (0x01)
  A1                            Map with 1 entry
  8A "user_agent"               Tiny string key (10 chars)
  D0 10 "fingerprintx/1.0"      String8 value (16 chars)

SUCCESS Response (signature 0x70):
  Contains map with "server" field: "Neo4j/{version}"

Version Compatibility:
  - Bolt 4.x: Neo4j 4.0+
  - Bolt 5.x: Neo4j 5.0+
*/

package neo4j

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type NEO4JPlugin struct{}
type NEO4JTLSPlugin struct{}

const NEO4J = "neo4j"

const (
	SUCCESS_SIGNATURE = 0x70
	FAILURE_SIGNATURE = 0x7F
)

var boltMagic = []byte{0x60, 0x60, 0xB0, 0x17}

func init() {
	plugins.RegisterPlugin(&NEO4JPlugin{})
	plugins.RegisterPlugin(&NEO4JTLSPlugin{})
}

func DetectNeo4j(conn net.Conn, timeout time.Duration) (string, bool, error) {
	// PHASE 1: Bolt Handshake (Detection)
	handshake := buildBoltHandshake()
	response, err := utils.SendRecv(conn, handshake, timeout)
	if err != nil {
		return "", false, err
	}
	if len(response) == 0 {
		return "", false, &utils.InvalidResponseError{Service: NEO4J}
	}

	isBolt, err := checkBoltHandshakeResponse(response)
	if !isBolt {
		return "", false, err
	}

	// PHASE 2: HELLO Message (Enrichment)
	helloMsg := buildHelloMessage()
	response, err = utils.SendRecv(conn, helloMsg, timeout)
	if err != nil {
		// Handshake succeeded but HELLO failed - still detected as Bolt
		// but we can't get version
		return "", true, nil
	}
	if len(response) == 0 {
		return "", true, nil
	}

	serverStr, isSuccess, err := parseHelloResponse(response)
	if !isSuccess || err != nil {
		// Could not parse HELLO response, but Bolt was detected
		return "", true, nil
	}

	// Check if this is specifically Neo4j (not TuGraph, etc.)
	version := parseNeo4jVersion(serverStr)
	if version == "" {
		// This is a Bolt server but not Neo4j
		// We could return the server string here for other implementations
		return "", true, nil
	}

	return version, true, nil
}

func (p *NEO4JPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	version, detected, err := DetectNeo4j(conn, timeout)
	if !detected {
		return nil, err
	}

	payload := plugins.ServiceNeo4j{}
	if version != "" {
		cpe := buildNeo4jCPE(version)
		if cpe != "" {
			payload.CPEs = []string{cpe}
		}
	}

	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *NEO4JPlugin) PortPriority(port uint16) bool {
	return port == 7687
}

func (p *NEO4JPlugin) Name() string {
	return NEO4J
}

func (p *NEO4JPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *NEO4JPlugin) Priority() int {
	// Run before HTTP (100) since Neo4j uses a dedicated port
	return 50
}

func (p *NEO4JTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	version, detected, err := DetectNeo4j(conn, timeout)
	if !detected {
		return nil, err
	}

	payload := plugins.ServiceNeo4j{}
	if version != "" {
		cpe := buildNeo4jCPE(version)
		if cpe != "" {
			payload.CPEs = []string{cpe}
		}
	}

	return plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS), nil
}

func (p *NEO4JTLSPlugin) PortPriority(port uint16) bool {
	return port == 7687
}

func (p *NEO4JTLSPlugin) Name() string {
	return NEO4J
}

func (p *NEO4JTLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *NEO4JTLSPlugin) Priority() int {
	return 51
}

// buildBoltHandshake constructs the Bolt protocol handshake message.
// The handshake consists of magic bytes followed by four protocol version proposals.
//
// Returns:
//   - []byte: 20-byte handshake message
func buildBoltHandshake() []byte {
	handshake := make([]byte, 20)
	copy(handshake[0:4], boltMagic)
	binary.BigEndian.PutUint32(handshake[4:8], 0x00000404)   // v4.4
	binary.BigEndian.PutUint32(handshake[8:12], 0x00000304)  // v4.3
	binary.BigEndian.PutUint32(handshake[12:16], 0x00000204) // v4.2
	binary.BigEndian.PutUint32(handshake[16:20], 0x00000104) // v4.1
	return handshake
}

// buildHelloMessage constructs a HELLO message in PackStream format with chunking.
// The HELLO message initiates authentication and returns server metadata.
//
// Returns:
//   - []byte: Chunked HELLO message ready to send
func buildHelloMessage() []byte {
	userAgent := []byte("user_agent")
	userAgentValue := []byte("fingerprintx/1.0")

	body := make([]byte, 0, 32)
	body = append(body, 0xB1, 0x01)                      // Structure(1 field), tag=HELLO
	body = append(body, 0xA1)                            // Map with 1 entry
	body = append(body, 0x80|byte(len(userAgent)))       // Tiny string marker for key
	body = append(body, userAgent...)                    // Key: "user_agent"
	body = append(body, 0xD0, byte(len(userAgentValue))) // String8 marker for value
	body = append(body, userAgentValue...)               // Value: "fingerprintx/1.0"

	// Chunk the message: [2-byte length] [body] [00 00 terminator]
	msg := make([]byte, 2+len(body)+2)
	binary.BigEndian.PutUint16(msg[0:2], uint16(len(body)))
	copy(msg[2:], body)

	return msg
}

// checkBoltHandshakeResponse validates the 4-byte Bolt handshake response.
// A valid response is a non-zero version number.
//
// Parameters:
//   - response: 4-byte response from server
//
// Returns:
//   - bool: true if valid Bolt response
//   - error: error details if validation fails
func checkBoltHandshakeResponse(response []byte) (bool, error) {
	if len(response) < 4 {
		return false, &utils.InvalidResponseErrorInfo{
			Service: NEO4J,
			Info:    "response too short for Bolt handshake",
		}
	}

	version := binary.BigEndian.Uint32(response[0:4])
	if version == 0 {
		return false, &utils.InvalidResponseErrorInfo{
			Service: NEO4J,
			Info:    "server rejected all proposed Bolt versions",
		}
	}

	return true, nil
}

// parseHelloResponse extracts the server string from a HELLO SUCCESS response.
// The response is in PackStream format with chunking.
//
// Parameters:
//   - response: Raw response bytes including chunk headers
//
// Returns:
//   - string: Server string (e.g., "Neo4j/5.13.0") if found
//   - bool: true if this is a valid SUCCESS response
//   - error: error details if parsing fails
func parseHelloResponse(response []byte) (string, bool, error) {
	if len(response) < 6 {
		return "", false, &utils.InvalidResponseErrorInfo{
			Service: NEO4J,
			Info:    "response too short for HELLO response",
		}
	}

	chunkLen := binary.BigEndian.Uint16(response[0:2])
	if int(chunkLen)+2 > len(response) {
		return "", false, &utils.InvalidResponseErrorInfo{
			Service: NEO4J,
			Info:    "chunk length exceeds response size",
		}
	}

	body := response[2 : 2+chunkLen]
	if len(body) < 2 {
		return "", false, &utils.InvalidResponseErrorInfo{
			Service: NEO4J,
			Info:    "response body too short",
		}
	}

	marker := body[0]
	if marker != 0xB1 {
		return "", false, &utils.InvalidResponseErrorInfo{
			Service: NEO4J,
			Info:    fmt.Sprintf("unexpected structure marker: %02x", marker),
		}
	}

	signature := body[1]
	if signature == FAILURE_SIGNATURE {
		// Check if FAILURE response contains Neo4j error codes (e.g., "Neo.ClientError.*")
		// This identifies Neo4j even when authentication is required
		if containsNeo4jErrorCode(body[2:]) {
			return "Neo4j/unknown", true, nil // Neo4j detected but version unknown
		}
		return "", false, &utils.InvalidResponseErrorInfo{
			Service: NEO4J,
			Info:    "server returned FAILURE response",
		}
	}
	if signature != SUCCESS_SIGNATURE {
		return "", false, &utils.InvalidResponseErrorInfo{
			Service: NEO4J,
			Info:    fmt.Sprintf("unexpected response signature: %02x", signature),
		}
	}

	serverStr := extractServerField(body[2:])

	return serverStr, true, nil
}

// containsNeo4jErrorCode checks if FAILURE response contains Neo4j-specific error codes.
// Neo4j errors start with "Neo." (e.g., "Neo.ClientError.Security.Unauthorized")
func containsNeo4jErrorCode(data []byte) bool {
	// Look for "Neo." pattern in the response data
	neo4jPrefix := []byte("Neo.")
	for i := 0; i <= len(data)-len(neo4jPrefix); i++ {
		if data[i] == 'N' && i+4 <= len(data) {
			if string(data[i:i+4]) == "Neo." {
				return true
			}
		}
	}
	return false
}

// extractServerField extracts the "server" field value from a PackStream map.
// This is a simplified parser optimized for the HELLO response format.
//
// Parameters:
//   - data: PackStream map bytes (after structure header)
//
// Returns:
//   - string: Server field value or empty string if not found
func extractServerField(data []byte) string {
	// Look for "server" key in the data
	// The key is encoded as tiny string (0x86 for 6 chars) followed by "server"
	serverKey := []byte{0x86, 's', 'e', 'r', 'v', 'e', 'r'}

	for pos := 0; pos < len(data)-len(serverKey); pos++ {
		// Look for the server key
		found := true
		for i := 0; i < len(serverKey); i++ {
			if data[pos+i] != serverKey[i] {
				found = false
				break
			}
		}

		if !found {
			continue
		}

		valuePos := pos + len(serverKey)
		if valuePos >= len(data) {
			return ""
		}

		marker := data[valuePos]
		if marker >= 0x80 && marker <= 0x8F {
			// Tiny string (length in low nibble)
			strLen := int(marker & 0x0F)
			if valuePos+1+strLen <= len(data) {
				return string(data[valuePos+1 : valuePos+1+strLen])
			}
		} else if marker == 0xD0 && valuePos+2 <= len(data) {
			// String8 (1-byte length)
			strLen := int(data[valuePos+1])
			if valuePos+2+strLen <= len(data) {
				return string(data[valuePos+2 : valuePos+2+strLen])
			}
		} else if marker == 0xD1 && valuePos+3 <= len(data) {
			// String16 (2-byte length)
			strLen := int(binary.BigEndian.Uint16(data[valuePos+1 : valuePos+3]))
			if valuePos+3+strLen <= len(data) {
				return string(data[valuePos+3 : valuePos+3+strLen])
			}
		}
		return ""
	}

	return ""
}

// parseNeo4jVersion extracts the version from a Neo4j server string.
// Returns empty string if the server is not Neo4j.
//
// Parameters:
//   - serverStr: Server string from HELLO response (e.g., "Neo4j/5.13.0")
//
// Returns:
//   - string: Version number (e.g., "5.13.0") or empty if not Neo4j
func parseNeo4jVersion(serverStr string) string {
	if !strings.HasPrefix(serverStr, "Neo4j/") {
		return "" // Not Neo4j, might be TuGraph or other Bolt implementation
	}
	version := strings.TrimPrefix(serverStr, "Neo4j/")
	// Remove any trailing metadata (spaces, etc.)
	version = strings.Split(version, " ")[0]
	return version
}

// buildNeo4jCPE constructs a CPE string for Neo4j.
//
// Parameters:
//   - version: Neo4j version string (e.g., "5.13.0")
//
// Returns:
//   - string: CPE string or empty if version is empty
func buildNeo4jCPE(version string) string {
	if version == "" || version == "unknown" {
		return "" // No CPE without a real version
	}
	return fmt.Sprintf("cpe:2.3:a:neo4j:neo4j:%s:*:*:*:*:*:*:*", version)
}
