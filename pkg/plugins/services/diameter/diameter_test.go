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
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	readData  []byte
	writeData []byte
	readErr   error
	writeErr  error
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	n = copy(b, m.readData)
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// buildMockCEA creates a valid Capabilities-Exchange-Answer for testing
func buildMockCEA(productName string, firmwareRevision uint32, includeVersion bool) []byte {
	// Diameter Header (20 bytes)
	header := make([]byte, 20)
	// Version = 1
	header[0] = 1
	// Command Flags: R-bit cleared (0x00) for answer
	header[4] = 0x00
	// Command Code = 257 (CER/CEA)
	binary.BigEndian.PutUint32(header[4:8], 257)
	header[4] = 0x00 // Overwrite flags byte
	// Application-ID = 0
	binary.BigEndian.PutUint32(header[8:12], 0)
	// Hop-by-Hop ID
	binary.BigEndian.PutUint32(header[12:16], 12345)
	// End-to-End ID
	binary.BigEndian.PutUint32(header[16:20], 67890)

	// Build AVPs
	avps := []byte{}

	// Result-Code AVP (Code 268, Mandatory) - Value: 2001 (DIAMETER_SUCCESS)
	avps = append(avps, buildTestAVP(268, true, encodeTestUnsigned32(2001))...)

	// Origin-Host AVP (Code 264, Mandatory)
	avps = append(avps, buildTestAVP(264, true, []byte("test.diameter.local\x00"))...)

	// Origin-Realm AVP (Code 296, Mandatory)
	avps = append(avps, buildTestAVP(296, true, []byte("local\x00"))...)

	// Host-IP-Address AVP (Code 257, Mandatory)
	// Address format: AddressType (2 bytes) + Address
	// AddressType 1 = IPv4
	ipAddr := []byte{0x00, 0x01, 127, 0, 0, 1} // IPv4: 127.0.0.1
	avps = append(avps, buildTestAVP(257, true, ipAddr)...)

	// Vendor-Id AVP (Code 266, Mandatory)
	avps = append(avps, buildTestAVP(266, true, encodeTestUnsigned32(0))...)

	// Product-Name AVP (Code 269, Mandatory)
	if productName != "" {
		productBytes := append([]byte(productName), 0x00) // Null-terminated
		avps = append(avps, buildTestAVP(269, true, productBytes)...)
	}

	// Firmware-Revision AVP (Code 267, Optional)
	if includeVersion {
		avps = append(avps, buildTestAVP(267, false, encodeTestUnsigned32(firmwareRevision))...)
	}

	// Update message length in header
	totalLength := len(header) + len(avps)
	// Bytes 1-3 contain the message length (24-bit big-endian)
	header[1] = byte((totalLength >> 16) & 0xFF)
	header[2] = byte((totalLength >> 8) & 0xFF)
	header[3] = byte(totalLength & 0xFF)

	return append(header, avps...)
}

// buildTestAVP constructs a Diameter AVP for testing
func buildTestAVP(code uint32, mandatory bool, data []byte) []byte {
	// AVP Header: Code (4 bytes) + Flags (1 byte) + Length (3 bytes)
	header := make([]byte, 8)

	// AVP Code
	binary.BigEndian.PutUint32(header[0:4], code)

	// Flags: M-bit for mandatory AVPs
	flags := byte(0)
	if mandatory {
		flags |= 0x40 // M-bit
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

// encodeTestUnsigned32 encodes a uint32 in big-endian format for testing
func encodeTestUnsigned32(value uint32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return data
}

// TestPortPriority verifies that port 3868 is recognized as the default Diameter port
func TestPortPriority(t *testing.T) {
	plugin := &DIAMETERPlugin{}

	tests := []struct {
		name     string
		port     uint16
		expected bool
	}{
		{"Diameter default port", 3868, true},
		{"Non-Diameter port", 8080, false},
		{"Zero port", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.PortPriority(tt.port)
			if result != tt.expected {
				t.Errorf("PortPriority(%d) = %v, want %v", tt.port, result, tt.expected)
			}
		})
	}
}

// TestName verifies that the plugin returns "diameter" as its name
func TestName(t *testing.T) {
	plugin := &DIAMETERPlugin{}
	if plugin.Name() != "diameter" {
		t.Errorf("Name() = %s, want diameter", plugin.Name())
	}
}

// TestType verifies that the plugin returns TCP as its protocol type
func TestType(t *testing.T) {
	plugin := &DIAMETERPlugin{}
	if plugin.Type() != plugins.TCP {
		t.Errorf("Type() = %v, want plugins.TCP", plugin.Type())
	}
}

// TestPriority verifies that the plugin priority is in the expected range
func TestPriority(t *testing.T) {
	plugin := &DIAMETERPlugin{}
	priority := plugin.Priority()
	if priority < 50 || priority > 70 {
		t.Errorf("Priority() = %d, want between 50 and 70", priority)
	}
}

// TestRunWithValidCEA tests successful detection with a valid CEA response
func TestRunWithValidCEA(t *testing.T) {
	plugin := &DIAMETERPlugin{}

	tests := []struct {
		name              string
		productName       string
		firmwareRevision  uint32
		includeVersion    bool
		expectedVersion   string
		expectedVendor    string
	}{
		{
			name:             "FreeDiameter with version 1.5.0",
			productName:      "freeDiameter",
			firmwareRevision: 10500,
			includeVersion:   true,
			expectedVersion:  "1.5.0",
			expectedVendor:   "freediameter",
		},
		{
			name:             "FreeDiameter with version 1.2.1",
			productName:      "freeDiameter",
			firmwareRevision: 10201,
			includeVersion:   true,
			expectedVersion:  "1.2.1",
			expectedVendor:   "freediameter",
		},
		{
			name:             "Open5GS with version",
			productName:      "Open5GS",
			firmwareRevision: 20700,
			includeVersion:   true,
			expectedVersion:  "2.7.0",
			expectedVendor:   "open5gs",
		},
		{
			name:            "FreeDiameter without version",
			productName:     "freeDiameter",
			includeVersion:  false,
			expectedVersion: "",
			expectedVendor:  "freediameter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCEA := buildMockCEA(tt.productName, tt.firmwareRevision, tt.includeVersion)
			conn := &mockConn{
				readData: mockCEA,
			}

			target := plugins.Target{
				Address: netip.MustParseAddrPort("127.0.0.1:3868"),
			}

			service, err := plugin.Run(conn, 5*time.Second, target)
			if err != nil {
				t.Fatalf("Run() error = %v, want nil", err)
			}

			if service == nil {
				t.Fatal("Run() returned nil service")
			}

			if service.Protocol != "diameter" {
				t.Errorf("service.Protocol = %s, want diameter", service.Protocol)
			}

			if service.Version != tt.expectedVersion {
				t.Errorf("service.Version = %s, want %s", service.Version, tt.expectedVersion)
			}

			// Parse metadata to verify vendor
			var metadata ServiceDiameter
			if err := json.Unmarshal(service.Raw, &metadata); err != nil {
				t.Fatalf("Failed to unmarshal metadata: %v", err)
			}

			// Check CPE format
			if len(metadata.CPEs) > 0 {
				expectedCPEPrefix := fmt.Sprintf("cpe:2.3:a:%s:", tt.expectedVendor)
				if !strings.HasPrefix(metadata.CPEs[0], expectedCPEPrefix) {
					t.Errorf("CPE = %s, want prefix %s", metadata.CPEs[0], expectedCPEPrefix)
				}
			}
		})
	}
}

// TestRunWithInvalidResponse tests handling of invalid responses
func TestRunWithInvalidResponse(t *testing.T) {
	plugin := &DIAMETERPlugin{}

	tests := []struct {
		name     string
		response []byte
	}{
		{
			name:     "Empty response",
			response: []byte{},
		},
		{
			name:     "Response too short",
			response: []byte{0x01, 0x00, 0x00},
		},
		{
			name: "Invalid version",
			response: []byte{
				0x02, 0x00, 0x00, 0x14, // Version 2 (invalid)
				0x00, 0x00, 0x01, 0x01, // Command Code
				0x00, 0x00, 0x00, 0x00, // Application-ID
				0x00, 0x00, 0x30, 0x39, // Hop-by-Hop
				0x00, 0x01, 0x09, 0x32, // End-to-End
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{
				readData: tt.response,
			}

			target := plugins.Target{
				Address: netip.MustParseAddrPort("127.0.0.1:3868"),
			}

			service, err := plugin.Run(conn, 5*time.Second, target)
			if err == nil {
				t.Error("Run() error = nil, want error for invalid response")
			}
			if service != nil {
				t.Errorf("Run() returned service %v, want nil for invalid response", service)
			}
		})
	}
}

// TestRunWithNonSuccessResultCode tests handling of Result-Code != 2001
func TestRunWithNonSuccessResultCode(t *testing.T) {
	plugin := &DIAMETERPlugin{}

	// Build CEA with Result-Code = 3010 (DIAMETER_NO_COMMON_APPLICATION)
	// Use buildMockCEA but modify the Result-Code after building
	mockCEA := buildMockCEA("test-diameter", 0, false)

	// Find and replace Result-Code AVP (Code 268) value from 2001 to 3010
	// The Result-Code AVP is after the header (20 bytes)
	// AVP structure: Code (4) + Flags (1) + Length (3) + Data (4) = 12 bytes (padded to 12)
	// We need to find the Result-Code AVP and update its value
	offset := 20
	for offset < len(mockCEA)-12 {
		avpCode := binary.BigEndian.Uint32(mockCEA[offset:offset+4])
		if avpCode == 268 { // Result-Code AVP
			// Update the value (offset+8 is where the Unsigned32 value starts)
			binary.BigEndian.PutUint32(mockCEA[offset+8:offset+12], 3010)
			break
		}
		// Move to next AVP (get AVP length and add padding)
		avpLength := (uint32(mockCEA[offset+5]) << 16) | (uint32(mockCEA[offset+6]) << 8) | uint32(mockCEA[offset+7])
		paddedLength := avpLength
		if avpLength%4 != 0 {
			paddedLength += 4 - (avpLength % 4)
		}
		offset += int(paddedLength)
	}

	conn := &mockConn{
		readData: mockCEA,
	}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:3868"),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)

	// Should return service but without version (detection succeeds even with error code)
	if err != nil {
		t.Errorf("Run() error = %v, want nil (detection should succeed)", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil service, want valid service")
	}
	if service.Protocol != "diameter" {
		t.Errorf("service.Protocol = %s, want diameter", service.Protocol)
	}
}

// TestDecodeFirmwareRevision tests the version decoding logic
func TestDecodeFirmwareRevision(t *testing.T) {
	tests := []struct {
		name             string
		firmwareRevision uint32
		expectedVersion  string
	}{
		{"Version 1.5.0", 10500, "1.5.0"},
		{"Version 1.4.0", 10400, "1.4.0"},
		{"Version 1.2.1", 10201, "1.2.1"},
		{"Version 1.0.3", 10003, "1.0.3"},
		{"Version 2.0.0", 20000, "2.0.0"},
		{"Zero version", 0, "0.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := decodeFirmwareRevision(tt.firmwareRevision)
			if version != tt.expectedVersion {
				t.Errorf("decodeFirmwareRevision(%d) = %s, want %s", tt.firmwareRevision, version, tt.expectedVersion)
			}
		})
	}
}

// TestIdentifyVendor tests vendor identification from Product-Name
func TestIdentifyVendor(t *testing.T) {
	tests := []struct {
		name            string
		productName     string
		expectedVendor  string
		expectedProduct string
	}{
		{"FreeDiameter", "freeDiameter", "freediameter", "freediameter"},
		{"Open5GS", "Open5GS", "open5gs", "open5gs"},
		{"Oracle", "Oracle Communications", "oracle", "diameter"},
		{"Ericsson", "Ericsson Diameter", "ericsson", "diameter"},
		{"Unknown", "CustomDiameter", "*", "diameter"},
		{"Empty", "", "*", "diameter"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vendor, product := identifyVendor(tt.productName)
			if vendor != tt.expectedVendor {
				t.Errorf("identifyVendor(%s) vendor = %s, want %s", tt.productName, vendor, tt.expectedVendor)
			}
			if product != tt.expectedProduct {
				t.Errorf("identifyVendor(%s) product = %s, want %s", tt.productName, product, tt.expectedProduct)
			}
		})
	}
}
