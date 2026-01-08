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
Package smpp implements fingerprinting for the SMPP (Short Message Peer-to-Peer) protocol.

SMPP is a telecommunications protocol used for exchanging SMS messages between SMS gateways
and message centers. Detection uses a two-phase approach with fallback:

Phase 1a: Detection via enquire_link (preferred)
  - Send enquire_link PDU (command_id 0x00000015)
  - Validate enquire_link_resp (command_id 0x80000015)
  - If successful, proceed to enrichment

Phase 1b: Fallback detection via bind_transceiver
  - Some servers only respond to enquire_link when already bound (non-standard)
  - If enquire_link fails, send bind_transceiver with dummy credentials
  - ANY valid SMPP response confirms protocol (including auth errors, generic_nack)
  - Cache response to avoid resending during enrichment

Phase 2: Enrichment via bind_transceiver
  - Use cached response from Phase 1b if available
  - Otherwise, attempt bind_transceiver with dummy credentials
  - Extract system_id from bind_transceiver_resp (even on auth error)
  - Parse sc_interface_version TLV (tag 0x0210) for protocol version
  - Identify vendor from system_id patterns

PDU Structure (16-byte header):
  Offset  Size  Field            Description
  0       4     command_length   Total PDU length (big-endian)
  4       4     command_id       Operation identifier (big-endian)
  8       4     command_status   Result code (big-endian)
  12      4     sequence_number  Request/response correlation (big-endian)

Key Command IDs:
  - enquire_link: 0x00000015
  - enquire_link_resp: 0x80000015
  - bind_transceiver: 0x00000009
  - bind_transceiver_resp: 0x80000009
  - generic_nack: 0x80000000

Error codes confirming SMPP (even on auth failure):
  - ESME_RINVPASWD (0x0E): Invalid password
  - ESME_RINVSYSID (0x0F): Invalid system_id
  - ESME_RALYBND (0x05): Already bound
*/
package smpp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

const (
	SMPP                   = "smpp"
	MIN_RESPONSE_SIZE      = 16
	PDU_HEADER_SIZE        = 16
	CMD_ENQUIRE_LINK       = 0x00000015
	CMD_ENQUIRE_LINK_RESP  = 0x80000015
	CMD_BIND_TRANSCEIVER   = 0x00000009
	CMD_BIND_TRANSCEIVER_RESP = 0x80000009
	CMD_GENERIC_NACK       = 0x80000000
	STATUS_OK              = 0x00000000
	TLV_SC_INTERFACE_VERSION = 0x0210
)

type SMPPPlugin struct{}

// VendorInfo holds detected vendor and product information
type VendorInfo struct {
	Vendor  string
	Product string
}

func init() {
	plugins.RegisterPlugin(&SMPPPlugin{})
}

func (p *SMPPPlugin) PortPriority(port uint16) bool {
	return port == 2775 || port == 2776
}

func (p *SMPPPlugin) Name() string {
	return SMPP
}

func (p *SMPPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *SMPPPlugin) Priority() int {
	return 55 // After common services, before low-priority protocols
}

func (p *SMPPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Phase 1: Detection with fallback (enquire_link → bind_transceiver)
	isValid, cachedBindResp, err := detectSMPP(conn, timeout)
	if err != nil || !isValid {
		return nil, nil
	}

	// Phase 2: Enrichment via bind_transceiver (reuse cached response if available)
	version, systemID, vendorInfo := enrichSMPP(conn, timeout, cachedBindResp)

	// Generate CPE
	cpe := buildSMPPCPE(vendorInfo.Vendor, vendorInfo.Product, version)
	cpes := []string{}
	if cpe != "" {
		cpes = append(cpes, cpe)
	}

	payload := plugins.ServiceSMPP{
		CPEs:            cpes,
		ProtocolVersion: version,
		SystemID:        systemID,
		Vendor:          vendorInfo.Vendor,
		Product:         vendorInfo.Product,
	}

	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

// detectSMPP performs Phase 1 detection with fallback strategy
// Returns: (detected bool, cachedBindResponse []byte, error)
//
// Phase 1a: Try enquire_link first (preferred method)
// Phase 1b: If enquire_link fails, try bind_transceiver as fallback
//
// Some SMPP servers only respond to enquire_link after binding (non-standard behavior).
// The fallback ensures detection succeeds even on these servers.
// If bind_transceiver is used for detection, the response is cached to avoid resending during enrichment.
func detectSMPP(conn net.Conn, timeout time.Duration) (bool, []byte, error) {
	// Phase 1a: Try enquire_link first (preferred, spec-compliant method)
	enquireLinkPDU := buildEnquireLinkPDU()
	response, err := utils.SendRecv(conn, enquireLinkPDU, timeout)

	// If enquire_link succeeds, no fallback needed
	if err == nil && isValidSMPPResponse(response, CMD_ENQUIRE_LINK_RESP) {
		return true, nil, nil
	}

	// Phase 1b: Fallback to bind_transceiver
	// Some servers require binding before responding to enquire_link (non-standard)
	bindPDU := buildBindTransceiverPDU()
	bindResponse, bindErr := utils.SendRecv(conn, bindPDU, timeout)
	if bindErr != nil {
		// Both enquire_link and bind_transceiver failed - not an SMPP server
		return false, nil, bindErr
	}

	// Validate bind_transceiver response
	// Accept ANY valid SMPP response, including:
	// - bind_transceiver_resp with STATUS_OK
	// - bind_transceiver_resp with auth errors (ESME_RINVPASWD, ESME_RINVSYSID, etc.)
	// - generic_nack (0x80000000)
	// All of these confirm the server speaks SMPP protocol
	if isValidSMPPResponse(bindResponse, CMD_BIND_TRANSCEIVER_RESP) {
		// Cache bind response to avoid resending during enrichment
		return true, bindResponse, nil
	}

	// Neither enquire_link nor bind_transceiver produced valid SMPP response
	return false, nil, &utils.InvalidResponseError{Service: SMPP}
}

// enrichSMPP performs Phase 2 enrichment using bind_transceiver
// Returns: (version, systemID, vendorInfo)
//
// If cachedBindResp is provided (from fallback detection), reuse it to avoid resending bind_transceiver.
// Otherwise, send a new bind_transceiver request for enrichment.
func enrichSMPP(conn net.Conn, timeout time.Duration, cachedBindResp []byte) (string, string, VendorInfo) {
	var response []byte

	// Use cached bind response if available (from Phase 1b fallback)
	if len(cachedBindResp) >= MIN_RESPONSE_SIZE {
		response = cachedBindResp
	} else {
		// No cached response - send bind_transceiver for enrichment
		bindPDU := buildBindTransceiverPDU()
		var err error
		response, err = utils.SendRecv(conn, bindPDU, timeout)
		if err != nil || len(response) < MIN_RESPONSE_SIZE {
			// Enrichment failed, but detection succeeded
			return "", "", VendorInfo{Vendor: "*", Product: "smpp"}
		}
	}

	// Parse response (works even on auth error)
	version := extractProtocolVersion(response)
	systemID := extractSystemID(response)
	vendorInfo := identifyVendor(systemID)

	// Default to 3.4 if bind_transceiver succeeded (requires 3.4+)
	if version == "" && isValidSMPPResponse(response, CMD_BIND_TRANSCEIVER_RESP) {
		version = "3.4"
	}

	return version, systemID, vendorInfo
}

// buildEnquireLinkPDU creates an enquire_link PDU (16 bytes, header only)
func buildEnquireLinkPDU() []byte {
	pdu := make([]byte, 16)
	binary.BigEndian.PutUint32(pdu[0:4], 16)                  // command_length
	binary.BigEndian.PutUint32(pdu[4:8], CMD_ENQUIRE_LINK)    // command_id
	binary.BigEndian.PutUint32(pdu[8:12], 0)                  // command_status
	binary.BigEndian.PutUint32(pdu[12:16], 1)                 // sequence_number
	return pdu
}

// buildBindTransceiverPDU creates a bind_transceiver PDU with dummy credentials
func buildBindTransceiverPDU() []byte {
	// PDU body fields (all null-terminated C-Octet Strings except last 3 bytes)
	systemID := "test\x00"           // 5 bytes
	password := "test\x00"           // 5 bytes
	systemType := "\x00"             // 1 byte (empty)
	interfaceVersion := byte(0x34)   // 1 byte (0x34 = 3.4)
	addrTON := byte(0)               // 1 byte
	addrNPI := byte(0)               // 1 byte
	addressRange := "\x00"           // 1 byte (empty)

	// Build body
	body := []byte(systemID + password + systemType)
	body = append(body, interfaceVersion, addrTON, addrNPI)
	body = append(body, []byte(addressRange)...)

	// Build PDU with header
	pduLen := PDU_HEADER_SIZE + len(body)
	pdu := make([]byte, pduLen)

	// Header
	binary.BigEndian.PutUint32(pdu[0:4], uint32(pduLen))           // command_length
	binary.BigEndian.PutUint32(pdu[4:8], CMD_BIND_TRANSCEIVER)     // command_id
	binary.BigEndian.PutUint32(pdu[8:12], 0)                       // command_status
	binary.BigEndian.PutUint32(pdu[12:16], 2)                      // sequence_number

	// Body
	copy(pdu[16:], body)

	return pdu
}

// isValidSMPPResponse validates SMPP response structure
func isValidSMPPResponse(response []byte, expectedCmdID uint32) bool {
	// Check minimum length
	if len(response) < MIN_RESPONSE_SIZE {
		return false
	}

	// Extract header fields
	cmdLength := binary.BigEndian.Uint32(response[0:4])
	cmdID := binary.BigEndian.Uint32(response[4:8])
	cmdStatus := binary.BigEndian.Uint32(response[8:12])

	// Validate command_length matches actual response length
	if cmdLength != uint32(len(response)) {
		return false
	}

	// Check if command_id matches expected response
	// For bind_transceiver_resp, also accept generic_nack or error statuses
	if cmdID == expectedCmdID {
		return true
	}

	// Accept generic_nack as valid SMPP response
	if cmdID == CMD_GENERIC_NACK {
		return true
	}

	// Accept bind_transceiver_resp with error status (confirms SMPP even on auth failure)
	if expectedCmdID == CMD_BIND_TRANSCEIVER_RESP && cmdID == CMD_BIND_TRANSCEIVER_RESP {
		// Error codes that confirm SMPP: ESME_RINVPASWD (0x0E), ESME_RINVSYSID (0x0F), ESME_RALYBND (0x05)
		if cmdStatus == 0x0E || cmdStatus == 0x0F || cmdStatus == 0x05 || cmdStatus == STATUS_OK {
			return true
		}
	}

	return false
}

// extractProtocolVersion extracts protocol version from sc_interface_version TLV
func extractProtocolVersion(response []byte) string {
	if len(response) < MIN_RESPONSE_SIZE {
		return ""
	}

	// Parse body after 16-byte header
	bodyStart := PDU_HEADER_SIZE

	// For bind_transceiver_resp, skip system_id (null-terminated)
	pos := bodyStart
	for pos < len(response) && response[pos] != 0 {
		pos++
	}
	pos++ // Skip null terminator

	// Parse TLVs (if any remain)
	for pos+4 <= len(response) {
		tag := binary.BigEndian.Uint16(response[pos : pos+2])
		length := binary.BigEndian.Uint16(response[pos+2 : pos+4])

		if tag == TLV_SC_INTERFACE_VERSION && length == 1 && pos+4+int(length) <= len(response) {
			versionByte := response[pos+4]
			// Map version byte to version string
			switch versionByte {
			case 0x33:
				return "3.3"
			case 0x34:
				return "3.4"
			case 0x50:
				return "5.0"
			default:
				return fmt.Sprintf("0x%02x", versionByte)
			}
		}

		pos += 4 + int(length)
	}

	return ""
}

// extractSystemID extracts system_id from bind_transceiver_resp
func extractSystemID(response []byte) string {
	if len(response) < MIN_RESPONSE_SIZE {
		return ""
	}

	// system_id starts at byte 16 (after header) and is null-terminated
	bodyStart := PDU_HEADER_SIZE
	endPos := bytes.IndexByte(response[bodyStart:], 0)
	if endPos == -1 {
		return ""
	}

	systemID := string(response[bodyStart : bodyStart+endPos])
	return systemID
}

// identifyVendor identifies vendor and product from system_id
func identifyVendor(systemID string) VendorInfo {
	if systemID == "" {
		return VendorInfo{Vendor: "*", Product: "smpp"}
	}

	// Normalize for case-insensitive matching
	sysIDLower := strings.ToLower(systemID)

	// Vendor detection patterns
	if strings.Contains(sysIDLower, "kannel") {
		return VendorInfo{Vendor: "kannel", Product: "kannel"}
	}
	if strings.Contains(sysIDLower, "melroselabssmsc") {
		return VendorInfo{Vendor: "melroselabs", Product: "smsc-simulator"}
	}
	if strings.Contains(sysIDLower, "smppsim") {
		return VendorInfo{Vendor: "seleniumsoftware", Product: "smppsim"}
	}
	if strings.Contains(sysIDLower, "jasmin") {
		return VendorInfo{Vendor: "jasmin", Product: "jasmin"}
	}

	// Default to generic SMPP with system_id as product
	return VendorInfo{Vendor: "*", Product: "smpp"}
}

// buildSMPPCPE generates a CPE (Common Platform Enumeration) string for SMPP servers
// Format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
func buildSMPPCPE(vendor, product, version string) string {
	if vendor == "" {
		vendor = "*"
	}
	if product == "" {
		product = "smpp"
	}
	if version == "" {
		version = "*"
	}

	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
}
