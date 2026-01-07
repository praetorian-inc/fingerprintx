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

package diameter

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
Diameter Protocol Fingerprinting

Diameter is the successor to RADIUS, used for Authentication, Authorization, and Accounting (AAA)
in 3GPP networks (LTE, 5G) and other telecommunications systems.

Detection Strategy:
  PHASE 1 - DETECTION:
    - Connect to TCP port 3868 (default Diameter port)
    - Send Capabilities-Exchange-Request (CER) message
    - Receive Capabilities-Exchange-Answer (CEA) message
    - Validate CEA structure (Diameter header, Result-Code AVP)

  PHASE 2 - ENRICHMENT:
    - Extract Product-Name AVP (Code 269) for vendor identification
    - Extract Firmware-Revision AVP (Code 267) for version detection
    - Decode FreeDiameter version encoding: MAJOR*10000 + MINOR*100 + PATCH
    - Generate CPE string for vulnerability tracking

Diameter Message Structure:
  Header (20 bytes):
    - Version (1 byte): MUST be 1
    - Message Length (3 bytes): Total message length in bytes
    - Command Flags (1 byte): R-bit for request/answer
    - Command Code (3 bytes): 257 for CER/CEA
    - Application-ID (4 bytes): 0 for Diameter Base Protocol
    - Hop-by-Hop ID (4 bytes): Random identifier
    - End-to-End ID (4 bytes): Random identifier

  AVP (Attribute-Value Pair) Structure:
    - AVP Code (4 bytes)
    - Flags (1 byte): V-bit (Vendor-Specific), M-bit (Mandatory), P-bit (Protected)
    - AVP Length (3 bytes): Header + data length
    - [Vendor-ID (4 bytes)]: Optional, if V-bit set
    - Data: Variable length
    - Padding: To 32-bit boundary

Key AVPs:
  - Result-Code (268): 2001 = DIAMETER_SUCCESS
  - Origin-Host (264): FQDN of peer
  - Origin-Realm (296): Realm of peer
  - Host-IP-Address (257): IP addresses
  - Vendor-Id (266): IANA enterprise number
  - Product-Name (269): Product identification (e.g., "freeDiameter")
  - Firmware-Revision (267): Version number (e.g., 10500 = v1.5.0)

Version Detection:
  FreeDiameter encoding: firmwareRev = (MAJOR * 10000) + (MINOR * 100) + PATCH
  Examples:
    - 10500 → "1.5.0"
    - 10201 → "1.2.1"
    - 10003 → "1.0.3"

CPE Format:
  - FreeDiameter: cpe:2.3:a:freediameter:freediameter:{version}:*:*:*:*:*:*:*
  - Open5GS: cpe:2.3:a:open5gs:open5gs:{version}:*:*:*:*:*:*:*
  - Unknown: cpe:2.3:a:*:diameter:*:*:*:*:*:*:*:*
*/

const (
	DIAMETER           = "diameter"
	DIAMETER_PORT      = 3868
	DIAMETER_VERSION   = 1
	CER_COMMAND_CODE   = 257
	R_BIT              = 0x80 // Request bit
	DIAMETER_SUCCESS   = 2001
	AVP_RESULT_CODE    = 268
	AVP_ORIGIN_HOST    = 264
	AVP_ORIGIN_REALM   = 296
	AVP_HOST_IP_ADDR   = 257
	AVP_VENDOR_ID      = 266
	AVP_PRODUCT_NAME   = 269
	AVP_FIRMWARE_REV   = 267
	M_BIT              = 0x40 // Mandatory bit
)

type DIAMETERPlugin struct{}

func init() {
	plugins.RegisterPlugin(&DIAMETERPlugin{})
}

// Run implements the main fingerprinting logic
func (p *DIAMETERPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Phase 1: Detection - send CER and receive CEA
	cea, err := detectDiameter(conn, timeout)
	if err != nil {
		return nil, err
	}

	// Phase 2: Enrichment - extract version and metadata
	productName, firmwareRev, err := enrichDiameter(cea)
	if err != nil {
		// Detection succeeded but enrichment failed - still return service
		metadata := ServiceDiameter{}
		return plugins.CreateServiceFrom(target, metadata, false, "", plugins.TCP), nil
	}

	// Identify vendor from Product-Name
	vendor, product := identifyVendor(productName)

	// Decode version from Firmware-Revision
	var version string
	if firmwareRev > 0 {
		version = decodeFirmwareRevision(firmwareRev)
	}

	// Build CPE
	cpe := buildCPE(vendor, product, version)

	// Create service with metadata
	metadata := ServiceDiameter{
		CPEs:    []string{cpe},
		Version: version,
		Vendor:  vendor,
		Product: product,
	}

	return plugins.CreateServiceFrom(target, metadata, false, version, plugins.TCP), nil
}

// PortPriority returns true if the port is 3868 (default Diameter port)
func (p *DIAMETERPlugin) PortPriority(port uint16) bool {
	return port == DIAMETER_PORT
}

// Name returns the protocol name
func (p *DIAMETERPlugin) Name() string {
	return DIAMETER
}

// Type returns the protocol type (TCP)
func (p *DIAMETERPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the plugin execution priority
// Diameter uses port 3868 exclusively, run at medium priority (after common services)
func (p *DIAMETERPlugin) Priority() int {
	return 60
}

// detectDiameter sends a CER message and validates the CEA response
func detectDiameter(conn net.Conn, timeout time.Duration) ([]byte, error) {
	// Build CER message
	cer := buildCER()

	// Send CER
	response, err := utils.SendRecv(conn, cer, timeout)
	if err != nil {
		return nil, err
	}

	// Validate CEA structure
	if err := validateCEA(response); err != nil {
		return nil, err
	}

	return response, nil
}

// buildCER constructs a Capabilities-Exchange-Request message
func buildCER() []byte {
	// Diameter Header (20 bytes)
	header := make([]byte, 20)

	// Version = 1
	header[0] = DIAMETER_VERSION

	// Command Flags: R-bit set (0x80) for request
	header[4] = R_BIT

	// Command Code = 257 (3 bytes in big-endian, starting at byte 5)
	binary.BigEndian.PutUint32(header[4:8], CER_COMMAND_CODE)
	header[4] = R_BIT // Restore flags after PutUint32

	// Application-ID = 0 (Diameter Base Protocol)
	binary.BigEndian.PutUint32(header[8:12], 0)

	// Hop-by-Hop ID (random)
	binary.BigEndian.PutUint32(header[12:16], 12345)

	// End-to-End ID (random)
	binary.BigEndian.PutUint32(header[16:20], 67890)

	// Build AVPs
	avps := []byte{}

	// Origin-Host AVP (Code 264, Mandatory)
	avps = append(avps, buildAVP(AVP_ORIGIN_HOST, true, []byte("fingerprintx.local\x00"))...)

	// Origin-Realm AVP (Code 296, Mandatory)
	avps = append(avps, buildAVP(AVP_ORIGIN_REALM, true, []byte("local\x00"))...)

	// Host-IP-Address AVP (Code 257, Mandatory)
	// Address format: AddressType (2 bytes) + Address
	// AddressType 1 = IPv4
	ipAddr := []byte{0x00, 0x01, 127, 0, 0, 1} // IPv4: 127.0.0.1
	avps = append(avps, buildAVP(AVP_HOST_IP_ADDR, true, ipAddr)...)

	// Vendor-Id AVP (Code 266, Mandatory)
	avps = append(avps, buildAVP(AVP_VENDOR_ID, true, encodeUnsigned32(0))...)

	// Product-Name AVP (Code 269, Mandatory)
	avps = append(avps, buildAVP(AVP_PRODUCT_NAME, true, []byte("fingerprintx\x00"))...)

	// Update message length in header
	totalLength := len(header) + len(avps)
	// Bytes 1-3 contain the message length (24-bit big-endian)
	header[1] = byte((totalLength >> 16) & 0xFF)
	header[2] = byte((totalLength >> 8) & 0xFF)
	header[3] = byte(totalLength & 0xFF)

	return append(header, avps...)
}

// buildAVP constructs a Diameter AVP
func buildAVP(code uint32, mandatory bool, data []byte) []byte {
	// AVP Header: Code (4 bytes) + Flags (1 byte) + Length (3 bytes)
	header := make([]byte, 8)

	// AVP Code
	binary.BigEndian.PutUint32(header[0:4], code)

	// Flags: M-bit for mandatory AVPs
	flags := byte(0)
	if mandatory {
		flags |= M_BIT
	}
	header[4] = flags

	// AVP Length (header + data)
	avpLength := 8 + len(data)
	header[5] = byte((avpLength >> 16) & 0xFF)
	header[6] = byte((avpLength >> 8) & 0xFF)
	header[7] = byte(avpLength & 0xFF)

	// Combine header and data
	avp := append(header, data...)

	// Pad to 32-bit boundary
	for len(avp)%4 != 0 {
		avp = append(avp, 0x00)
	}

	return avp
}

// encodeUnsigned32 encodes a uint32 in big-endian format
func encodeUnsigned32(value uint32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return data
}

// validateCEA validates the structure of a Capabilities-Exchange-Answer
func validateCEA(response []byte) error {
	// Minimum CEA size: Header (20) + minimal AVPs (~40)
	if len(response) < 60 {
		return &utils.InvalidResponseErrorInfo{
			Service: DIAMETER,
			Info:    "response too short for valid CEA",
		}
	}

	// Check version (byte 0)
	if response[0] != DIAMETER_VERSION {
		return &utils.InvalidResponseErrorInfo{
			Service: DIAMETER,
			Info:    fmt.Sprintf("invalid version: %d, expected 1", response[0]),
		}
	}

	// Check message length (bytes 1-3, 24-bit big-endian)
	msgLength := (uint32(response[1]) << 16) | (uint32(response[2]) << 8) | uint32(response[3])
	if len(response) < int(msgLength) {
		return &utils.InvalidResponseErrorInfo{
			Service: DIAMETER,
			Info:    fmt.Sprintf("incomplete response: got %d bytes, expected %d", len(response), msgLength),
		}
	}

	// Check command code (bytes 5-7, 24-bit big-endian)
	// Byte 4 contains flags, bytes 5-7 contain command code
	commandCode := (uint32(response[5]) << 16) | (uint32(response[6]) << 8) | uint32(response[7])
	if commandCode != CER_COMMAND_CODE {
		return &utils.InvalidResponseErrorInfo{
			Service: DIAMETER,
			Info:    fmt.Sprintf("invalid command code: %d, expected 257", commandCode),
		}
	}

	// Check R-bit is cleared (answer, not request)
	if response[4]&R_BIT != 0 {
		return &utils.InvalidResponseErrorInfo{
			Service: DIAMETER,
			Info:    "R-bit set in CEA (expected answer, not request)",
		}
	}

	return nil
}

// enrichDiameter extracts version and metadata from CEA
func enrichDiameter(cea []byte) (string, uint32, error) {
	// Parse AVPs starting after header (20 bytes)
	offset := 20
	var productName string
	var firmwareRev uint32

	for offset < len(cea) {
		// Need at least 8 bytes for AVP header
		if offset+8 > len(cea) {
			break
		}

		// Parse AVP header
		avpCode := binary.BigEndian.Uint32(cea[offset : offset+4])
		flags := cea[offset+4]
		avpLength := (uint32(cea[offset+5]) << 16) | (uint32(cea[offset+6]) << 8) | uint32(cea[offset+7])

		// Calculate data offset (skip Vendor-ID if V-bit set)
		dataOffset := offset + 8
		if flags&0x80 != 0 { // V-bit set
			dataOffset += 4
		}

		// Extract data length
		dataLength := int(avpLength) - (dataOffset - offset)
		if dataOffset+dataLength > len(cea) {
			break
		}

		// Extract data
		data := cea[dataOffset : dataOffset+dataLength]

		// Process specific AVPs
		switch avpCode {
		case AVP_PRODUCT_NAME:
			// UTF8String (null-terminated)
			productName = string(data)
			if idx := strings.IndexByte(productName, 0); idx != -1 {
				productName = productName[:idx]
			}

		case AVP_FIRMWARE_REV:
			// Unsigned32
			if len(data) >= 4 {
				firmwareRev = binary.BigEndian.Uint32(data[0:4])
			}
		}

		// Move to next AVP (account for padding to 32-bit boundary)
		paddedLength := avpLength
		if avpLength%4 != 0 {
			paddedLength += 4 - (avpLength % 4)
		}
		offset += int(paddedLength)
	}

	if productName == "" {
		return "", 0, fmt.Errorf("Product-Name AVP not found in CEA")
	}

	return productName, firmwareRev, nil
}

// decodeFirmwareRevision decodes FreeDiameter version from Firmware-Revision AVP
func decodeFirmwareRevision(firmwareRev uint32) string {
	major := firmwareRev / 10000
	minor := (firmwareRev % 10000) / 100
	patch := firmwareRev % 100
	return fmt.Sprintf("%d.%d.%d", major, minor, patch)
}

// identifyVendor maps Product-Name to vendor identifier for CPE
func identifyVendor(productName string) (vendor, product string) {
	productLower := strings.ToLower(productName)
	switch {
	case strings.Contains(productLower, "freediameter"):
		return "freediameter", "freediameter"
	case strings.Contains(productLower, "open5gs"):
		return "open5gs", "open5gs"
	case strings.Contains(productLower, "oracle"):
		return "oracle", "diameter"
	case strings.Contains(productLower, "ericsson"):
		return "ericsson", "diameter"
	default:
		return "*", "diameter"
	}
}

// buildCPE generates CPE 2.3 formatted string
func buildCPE(vendor, product, version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
}

// ServiceDiameter contains metadata for Diameter services
type ServiceDiameter struct {
	CPEs    []string `json:"cpes,omitempty"`
	Version string   `json:"version,omitempty"`
	Vendor  string   `json:"vendor,omitempty"`
	Product string   `json:"product,omitempty"`
}

// Type implements the Metadata interface
func (s ServiceDiameter) Type() string {
	return DIAMETER
}
