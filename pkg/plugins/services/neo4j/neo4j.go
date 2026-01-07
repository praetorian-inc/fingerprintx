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
  PHASE 1 - Bolt handshake (determines if the service speaks Bolt):
    - Send Bolt magic bytes (60 60 B0 17) followed by version proposals
    - If server responds with a non-zero 4-byte version number, it's a Bolt server
    - If server responds with zeros or closes connection, it's not Bolt

  PHASE 2 - Identification (verifies Neo4j specifically; extracts version when possible):
    - After successful handshake, send HELLO message
    - Parse SUCCESS response for "server" field (e.g., "Neo4j/5.13.0")
    - Verify "Neo4j/" prefix to distinguish from other Bolt implementations (TuGraph, etc.)
    - If "server" is missing and Bolt 5+, send LOGON with empty creds and treat Neo4j-specific FAILURE codes ("Neo.") as confirmation
    - Extract version number and generate CPE

Bolt Protocol Wire Format:

Handshake (20 bytes total):
  Magic:    60 60 B0 17         (4 bytes - identifies Bolt connection)
  Version1: 00 00 MIN MAJ       (4 bytes - preferred version, big-endian uint32)
  Version2: 00 00 MIN MAJ       (4 bytes - fallback version)
  Version3: 00 00 MIN MAJ       (4 bytes - fallback version)
  Version4: 00 00 MIN MAJ       (4 bytes - fallback version)

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
  - Bolt 6.0: Neo4j 2025.10+
*/

package neo4j

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
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
	HELLO_SIGNATURE   = 0x01
	LOGON_SIGNATURE   = 0x6A
)

var boltMagic = []byte{0x60, 0x60, 0xB0, 0x17}

func init() {
	plugins.RegisterPlugin(&NEO4JPlugin{})
	plugins.RegisterPlugin(&NEO4JTLSPlugin{})
}

func DetectNeo4j(conn net.Conn, timeout time.Duration) (string, bool, error) {
	// PHASE 1: Bolt handshake (service speaks Bolt)
	handshake := buildBoltHandshake()
	if err := utils.Send(conn, handshake, timeout); err != nil {
		return "", false, err
	}
	handshakeResp, err := recvExact(conn, 4, timeout)
	if err != nil {
		return "", false, err
	}
	if len(handshakeResp) == 0 {
		return "", false, nil
	}

	selected, ok, err := checkBoltHandshakeResponse(handshakeResp, boltHandshakeProposals())
	if !ok || err != nil {
		return "", false, nil
	}
	selectedMajor := byte(selected & 0xFF)

	// PHASE 2: HELLO (Neo4j identification + enrichment)
	if err := utils.Send(conn, buildHelloMessage(), timeout); err != nil {
		return "", false, err
	}
	helloResp, err := recvBoltMessageRaw(conn, timeout)
	if err != nil || len(helloResp) == 0 {
		return "", false, nil
	}

	serverStr, neo4j, err := parseHelloResponse(helloResp)
	if neo4j && err == nil {
		return parseNeo4jVersion(serverStr), true, nil
	}

	// If the server omits the "server" metadata, Bolt 5.1+ may still allow us to
	// confirm Neo4j by provoking a Neo4j-specific auth FAILURE via LOGON.
	if selectedMajor >= 5 && err == nil && serverStr == "" {
		if err := utils.Send(conn, buildLogonMessage(), timeout); err != nil {
			return "", false, err
		}
		logonResp, err := recvBoltMessageRaw(conn, timeout)
		if err == nil && len(logonResp) > 0 {
			_, neo4j, _ := parseHelloResponse(logonResp)
			if neo4j {
				return "", true, nil
			}
		}
	}

	return "", false, nil
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
	return -1
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
	return 0
}

func boltVersion(major, minor byte) uint32 {
	return uint32(minor)<<8 | uint32(major)
}

func boltHandshakeProposals() []uint32 {
	// Handshake slots are limited to 4 versions. We prioritize modern Bolt while
	// keeping Neo4j 4.1+ compatibility.
	return []uint32{
		boltVersion(6, 0), // Neo4j 2025.10+ can negotiate Bolt 6.0
		boltVersion(5, 0), // Neo4j 5.x negotiates Bolt 5.x (including 5.0)
		boltVersion(4, 4), // Neo4j 4.4 supports Bolt 4.4
		boltVersion(4, 1), // Neo4j 4.1 supports Bolt 4.1 (and newer 4.x also accept 4.1)
	}
}

// buildBoltHandshake constructs the 20-byte Bolt handshake: magic + 4 version proposals.
func buildBoltHandshake() []byte {
	proposals := boltHandshakeProposals()
	handshake := make([]byte, 20)
	copy(handshake[0:4], boltMagic)
	binary.BigEndian.PutUint32(handshake[4:8], proposals[0])
	binary.BigEndian.PutUint32(handshake[8:12], proposals[1])
	binary.BigEndian.PutUint32(handshake[12:16], proposals[2])
	binary.BigEndian.PutUint32(handshake[16:20], proposals[3])
	return handshake
}

func buildHelloMessage() []byte {
	userAgent := []byte("user_agent")
	userAgentValue := []byte("fingerprintx/1.0")

	// PackStream: B1=struct(1 field), 01=HELLO, A1=map(1 entry)
	body := make([]byte, 0, 32)
	body = append(body, 0xB1, HELLO_SIGNATURE)
	body = append(body, 0xA1)
	body = append(body, 0x80|byte(len(userAgent)))
	body = append(body, userAgent...)
	body = append(body, 0xD0, byte(len(userAgentValue)))
	body = append(body, userAgentValue...)

	// Wrap in chunk: [2-byte len][body][00 00]
	msg := make([]byte, 2+len(body)+2)
	binary.BigEndian.PutUint16(msg[0:2], uint16(len(body)))
	copy(msg[2:], body)
	return msg
}

func buildLogonMessage() []byte {
	body := make([]byte, 0, 96)
	body = append(body, 0xB1, LOGON_SIGNATURE)
	body = append(body, 0xA3) // map with 3 entries
	body = append(body, packstreamTinyString("scheme")...)
	body = append(body, packstreamTinyString("basic")...)
	body = append(body, packstreamTinyString("principal")...)
	body = append(body, packstreamTinyString("")...)
	body = append(body, packstreamTinyString("credentials")...)
	body = append(body, packstreamTinyString("")...)

	msg := make([]byte, 2+len(body)+2)
	binary.BigEndian.PutUint16(msg[0:2], uint16(len(body)))
	copy(msg[2:], body)
	return msg
}

func packstreamTinyString(s string) []byte {
	if len(s) > 15 {
		out := make([]byte, 0, 2+len(s))
		out = append(out, 0xD0, byte(len(s)))
		out = append(out, []byte(s)...)
		return out
	}
	out := make([]byte, 0, 1+len(s))
	out = append(out, 0x80|byte(len(s)))
	out = append(out, []byte(s)...)
	return out
}

// Returns (selected version, true, nil) if the server chose one of our proposals.
func checkBoltHandshakeResponse(response []byte, proposals []uint32) (uint32, bool, error) {
	if len(response) < 4 {
		return 0, false, &utils.InvalidResponseErrorInfo{
			Service: NEO4J,
			Info:    "response too short for Bolt handshake",
		}
	}

	version := binary.BigEndian.Uint32(response[0:4])
	if version == 0 {
		return 0, false, &utils.InvalidResponseErrorInfo{
			Service: NEO4J,
			Info:    "server rejected all proposed Bolt versions",
		}
	}

	offered := make(map[uint32]struct{}, len(proposals))
	for _, v := range proposals {
		offered[v] = struct{}{}
	}
	if _, ok := offered[version]; !ok {
		return version, false, &utils.InvalidResponseErrorInfo{
			Service: NEO4J,
			Info:    fmt.Sprintf("server selected unoffered Bolt version: %08x", version),
		}
	}

	return version, true, nil
}

// parseHelloResponse extracts server info from a chunked HELLO/LOGON response.
// Returns (server string, isNeo4j, error). isNeo4j is true if "Neo4j/" prefix
// is found in server field, or "Neo.*" error code appears in FAILURE response.
func parseHelloResponse(response []byte) (string, bool, error) {
	body, err := dechunkBoltMessage(response)
	if err != nil {
		return "", false, err
	}
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
		if containsNeo4jErrorCode(body[2:]) {
			return "", true, nil
		}
		return "", false, nil
	}
	if signature != SUCCESS_SIGNATURE {
		return "", false, &utils.InvalidResponseErrorInfo{
			Service: NEO4J,
			Info:    fmt.Sprintf("unexpected response signature: %02x", signature),
		}
	}

	serverStr := extractServerField(body[2:])
	if strings.HasPrefix(serverStr, "Neo4j/") {
		return serverStr, true, nil
	}
	return serverStr, false, nil
}

// containsNeo4jErrorCode checks if FAILURE response contains Neo4j-specific error codes.
// Neo4j errors start with "Neo." (e.g., "Neo.ClientError.Security.Unauthorized")
func containsNeo4jErrorCode(data []byte) bool {
	neo4jPrefix := []byte("Neo.")
	for i := 0; i <= len(data)-len(neo4jPrefix); i++ {
		if string(data[i:i+4]) == "Neo." {
			return true
		}
	}
	return false
}

// extractServerField finds the "server" key in a PackStream map and returns its value.
func extractServerField(data []byte) string {
	// PackStream tiny string: 0x86 = marker for 6-char string, followed by "server"
	serverKey := []byte{0x86, 's', 'e', 'r', 'v', 'e', 'r'}

	for pos := 0; pos < len(data)-len(serverKey); pos++ {
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

		// Parse PackStream string value: 0x8X=tiny, 0xD0=String8, 0xD1=String16
		marker := data[valuePos]
		if marker >= 0x80 && marker <= 0x8F {
			strLen := int(marker & 0x0F)
			if valuePos+1+strLen <= len(data) {
				return string(data[valuePos+1 : valuePos+1+strLen])
			}
		} else if marker == 0xD0 && valuePos+2 <= len(data) {
			strLen := int(data[valuePos+1])
			if valuePos+2+strLen <= len(data) {
				return string(data[valuePos+2 : valuePos+2+strLen])
			}
		} else if marker == 0xD1 && valuePos+3 <= len(data) {
			strLen := int(binary.BigEndian.Uint16(data[valuePos+1 : valuePos+3]))
			if valuePos+3+strLen <= len(data) {
				return string(data[valuePos+3 : valuePos+3+strLen])
			}
		}
		return ""
	}

	return ""
}

// dechunkBoltMessage reassembles a chunked Bolt message into a single body.
func dechunkBoltMessage(response []byte) ([]byte, error) {
	if len(response) < 4 {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: NEO4J,
			Info:    "response too short for chunked message",
		}
	}

	body := make([]byte, 0, len(response))
	pos := 0
	for {
		if pos+2 > len(response) {
			return nil, &utils.InvalidResponseErrorInfo{
				Service: NEO4J,
				Info:    "truncated chunk header",
			}
		}

		chunkLen := int(binary.BigEndian.Uint16(response[pos : pos+2]))
		pos += 2

		if chunkLen == 0 {
			break
		}
		if pos+chunkLen > len(response) {
			return nil, &utils.InvalidResponseErrorInfo{
				Service: NEO4J,
				Info:    "chunk length exceeds response size",
			}
		}

		body = append(body, response[pos:pos+chunkLen]...)
		pos += chunkLen
	}

	if len(body) == 0 {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: NEO4J,
			Info:    "empty chunked message body",
		}
	}
	return body, nil
}

func recvExact(conn net.Conn, n int, timeout time.Duration) ([]byte, error) {
	if n <= 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	read := 0
	for read < n {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return []byte{}, &utils.ReadTimeoutError{WrappedError: err}
		}
		m, err := conn.Read(buf[read:])
		if err != nil {
			var netErr net.Error
			if (errors.As(err, &netErr) && netErr.Timeout()) ||
				errors.Is(err, syscall.ECONNREFUSED) {
				return []byte{}, nil
			}
			return buf[:read], err
		}
		if m == 0 {
			break
		}
		read += m
	}
	return buf[:read], nil
}

// recvBoltMessageRaw reads a complete chunked Bolt message, handling TCP segmentation.
func recvBoltMessageRaw(conn net.Conn, timeout time.Duration) ([]byte, error) {
	const maxMessageBytes = 128 * 1024

	raw := make([]byte, 0, 4096)
	consumed := 0
	tmp := make([]byte, 4096)

	for {
		for {
			if consumed+2 > len(raw) {
				break
			}
			chunkLen := int(binary.BigEndian.Uint16(raw[consumed : consumed+2]))
			if chunkLen == 0 {
				consumed += 2
				return raw[:consumed], nil
			}
			if consumed+2+chunkLen > len(raw) {
				break
			}
			consumed += 2 + chunkLen
		}

		if len(raw) >= maxMessageBytes {
			return []byte{}, &utils.InvalidResponseErrorInfo{
				Service: NEO4J,
				Info:    "bolt message exceeds maximum size",
			}
		}

		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return []byte{}, &utils.ReadTimeoutError{WrappedError: err}
		}
		n, err := conn.Read(tmp)
		if err != nil {
			var netErr net.Error
			if (errors.As(err, &netErr) && netErr.Timeout()) ||
				errors.Is(err, syscall.ECONNREFUSED) {
				return []byte{}, nil
			}
			return raw, err
		}
		if n == 0 {
			return []byte{}, nil
		}
		raw = append(raw, tmp[:n]...)
	}
}

// parseNeo4jVersion extracts version from "Neo4j/X.Y.Z" server string.
func parseNeo4jVersion(serverStr string) string {
	if !strings.HasPrefix(serverStr, "Neo4j/") {
		return ""
	}
	version := strings.TrimPrefix(serverStr, "Neo4j/")
	return strings.Split(version, " ")[0]
}

// buildNeo4jCPE constructs a CPE 2.3 string for the given Neo4j version.
func buildNeo4jCPE(version string) string {
	if version == "" {
		return ""
	}
	return fmt.Sprintf("cpe:2.3:a:neo4j:neo4j:%s:*:*:*:*:*:*:*", version)
}
