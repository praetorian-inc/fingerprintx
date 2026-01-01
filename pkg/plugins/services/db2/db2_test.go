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
	"testing"
)

// Test buildEXCSAT message generation
func TestBuildEXCSAT(t *testing.T) {
	msg := buildEXCSAT()

	// Verify message length
	if len(msg) < MIN_DDM_LEN {
		t.Errorf("EXCSAT message too short: got %d bytes, expected at least %d", len(msg), MIN_DDM_LEN)
	}

	// Verify DDM magic byte
	if msg[2] != DDM_MAGIC {
		t.Errorf("Invalid DDM magic byte: got 0x%02X, expected 0x%02X", msg[2], DDM_MAGIC)
	}

	// Verify message length field matches actual length
	declaredLen := binary.BigEndian.Uint16(msg[0:2])
	if int(declaredLen) != len(msg) {
		t.Errorf("Length mismatch: declared %d, actual %d", declaredLen, len(msg))
	}

	// Verify EXCSAT codepoint
	codepoint := binary.BigEndian.Uint16(msg[4:6])
	if codepoint != EXCSAT {
		t.Errorf("Invalid codepoint: got 0x%04X, expected 0x%04X (EXCSAT)", codepoint, EXCSAT)
	}

	// Verify EXTNAM parameter is present
	// Parameter starts at offset 10
	if len(msg) < 14 { // 10 (header) + 2 (param length) + 2 (param codepoint)
		t.Error("Message too short to contain EXTNAM parameter")
		return
	}

	paramCodepoint := binary.BigEndian.Uint16(msg[12:14])
	if paramCodepoint != EXTNAM {
		t.Errorf("Invalid parameter codepoint: got 0x%04X, expected 0x%04X (EXTNAM)", paramCodepoint, EXTNAM)
	}
}

// Test DDM response validation with valid EXCSATRD
func TestCheckDDMResponse_ValidEXCSATRD(t *testing.T) {
	// Build a minimal valid EXCSATRD response
	// DDM Header: Length(2) + Magic(1) + Format(1) + Codepoint(2) + CorrelationID(2) + Length2(2)
	response := make([]byte, 10)
	binary.BigEndian.PutUint16(response[0:2], 10)     // Length
	response[2] = DDM_MAGIC                           // Magic
	response[3] = 0x02                                // Format
	binary.BigEndian.PutUint16(response[4:6], EXCSATRD) // Codepoint
	binary.BigEndian.PutUint16(response[6:8], 1)      // Correlation ID
	binary.BigEndian.PutUint16(response[8:10], 4)     // Length2

	valid, err := checkDDMResponse(response, EXCSATRD)
	if !valid {
		t.Errorf("Valid EXCSATRD marked as invalid: %v", err)
	}
	if err != nil {
		t.Errorf("Unexpected error for valid response: %v", err)
	}
}

// Test DDM response validation with invalid magic byte
func TestCheckDDMResponse_InvalidMagic(t *testing.T) {
	response := make([]byte, 10)
	binary.BigEndian.PutUint16(response[0:2], 10)
	response[2] = 0xFF // Invalid magic (should be 0xD0)
	binary.BigEndian.PutUint16(response[4:6], EXCSATRD)

	valid, err := checkDDMResponse(response, EXCSATRD)
	if valid {
		t.Error("Invalid magic byte should fail validation")
	}
	if err == nil {
		t.Error("Expected error for invalid magic byte")
	}
}

// Test DDM response validation with wrong codepoint
func TestCheckDDMResponse_WrongCodepoint(t *testing.T) {
	response := make([]byte, 10)
	binary.BigEndian.PutUint16(response[0:2], 10)
	response[2] = DDM_MAGIC
	binary.BigEndian.PutUint16(response[4:6], 0x9999) // Wrong codepoint

	valid, err := checkDDMResponse(response, EXCSATRD)
	if valid {
		t.Error("Wrong codepoint should fail validation")
	}
	if err == nil {
		t.Error("Expected error for wrong codepoint")
	}
}

// Test DDM response validation with truncated message
func TestCheckDDMResponse_TooShort(t *testing.T) {
	response := make([]byte, 5) // Too short for DDM header

	valid, err := checkDDMResponse(response, EXCSATRD)
	if valid {
		t.Error("Truncated message should fail validation")
	}
	if err == nil {
		t.Error("Expected error for truncated message")
	}
}

// Test parameter extraction from DDM message
func TestExtractParameter(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		codepoint uint16
		expected []byte
	}{
		{
			name: "Extract EXTNAM parameter",
			response: buildTestEXCSATRD(map[uint16][]byte{
				EXTNAM: []byte("DB2/LINUXX8664 11.5.6.0"),
			}),
			codepoint: EXTNAM,
			expected:  []byte("DB2/LINUXX8664 11.5.6.0"),
		},
		{
			name: "Extract SRVRLSLV parameter",
			response: buildTestEXCSATRD(map[uint16][]byte{
				SRVRLSLV: []byte("SQL11056"),
			}),
			codepoint: SRVRLSLV,
			expected:  []byte("SQL11056"),
		},
		{
			name: "Parameter not present",
			response: buildTestEXCSATRD(map[uint16][]byte{
				EXTNAM: []byte("DB2/LINUXX8664 11.5.6.0"),
			}),
			codepoint: SRVRLSLV, // Not in message
			expected:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractParameter(tt.response, tt.codepoint)
			if string(result) != string(tt.expected) {
				t.Errorf("extractParameter() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// Test version extraction from EXTNAM
func TestParseEXTNAMVersion(t *testing.T) {
	tests := []struct {
		extnam   string
		expected string
	}{
		{"DB2/LINUXX8664 11.5.6.0", "11.5.6.0"},
		{"DB2 for z/OS 12.1.0", "12.1.0"},
		{"DB2/AIX64 10.5.0.9", "10.5.0.9"},
		{"DB2/NT64 9.7.0.11", "9.7.0.11"},
		{"DB2", ""}, // No version
		{"", ""},    // Empty
	}

	for _, tt := range tests {
		t.Run(tt.extnam, func(t *testing.T) {
			result := parseEXTNAMVersion(tt.extnam)
			if result != tt.expected {
				t.Errorf("parseEXTNAMVersion(%q) = %q, expected %q", tt.extnam, result, tt.expected)
			}
		})
	}
}

// Test SRVRLSLV decoding
func TestDecodeSRVRLSLV(t *testing.T) {
	tests := []struct {
		srvrlslv string
		expected string
	}{
		{"SQL11056", "11.5.6"},
		{"SQL10050", "10.5.0"},
		{"SQL09074", "9.7.4"},
		{"SQL12010", "12.1.0"},
		{"INVALID", ""}, // Invalid format
		{"", ""},        // Empty
	}

	for _, tt := range tests {
		t.Run(tt.srvrlslv, func(t *testing.T) {
			result := decodeSRVRLSLV(tt.srvrlslv)
			if result != tt.expected {
				t.Errorf("decodeSRVRLSLV(%q) = %q, expected %q", tt.srvrlslv, result, tt.expected)
			}
		})
	}
}

// Test server type identification
func TestIdentifyServerType(t *testing.T) {
	tests := []struct {
		extnam   string
		expected string
	}{
		{"DB2/LINUXX8664 11.5.6.0", "DB2"},
		{"DB2 for z/OS", "DB2"},
		{"Apache Derby Network Server", "Derby"},
		{"Informix Dynamic Server", "Informix"},
		{"Unknown Server", "unknown"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.extnam, func(t *testing.T) {
			result := identifyServerType(tt.extnam)
			if result != tt.expected {
				t.Errorf("identifyServerType(%q) = %q, expected %q", tt.extnam, result, tt.expected)
			}
		})
	}
}

// Test metadata extraction from EXCSATRD
func TestParseEXCSATRDMetadata(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected db2Metadata
	}{
		{
			name: "DB2 with version in EXTNAM",
			response: buildTestEXCSATRD(map[uint16][]byte{
				EXTNAM:   []byte("DB2/LINUXX8664 11.5.6.0"),
				SRVNAM:   []byte("DB2INST1"),
				SRVRLSLV: []byte("SQL11056"),
			}),
			expected: db2Metadata{
				ServerName: "DB2INST1",
				Version:    "11.5.6.0",
				ServerType: "DB2",
			},
		},
		{
			name: "DB2 with version only in SRVRLSLV",
			response: buildTestEXCSATRD(map[uint16][]byte{
				EXTNAM:   []byte("DB2/AIX64"),
				SRVNAM:   []byte("SAMPLE"),
				SRVRLSLV: []byte("SQL10050"),
			}),
			expected: db2Metadata{
				ServerName: "SAMPLE",
				Version:    "10.5.0",
				ServerType: "DB2",
			},
		},
		{
			name: "Derby server",
			response: buildTestEXCSATRD(map[uint16][]byte{
				EXTNAM: []byte("Apache Derby Network Server"),
			}),
			expected: db2Metadata{
				ServerName: "",
				Version:    "",
				ServerType: "Derby",
			},
		},
		{
			name: "Informix server",
			response: buildTestEXCSATRD(map[uint16][]byte{
				EXTNAM: []byte("Informix Dynamic Server"),
			}),
			expected: db2Metadata{
				ServerName: "",
				Version:    "",
				ServerType: "Informix",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseEXCSATRDMetadata(tt.response)
			if result.ServerName != tt.expected.ServerName {
				t.Errorf("ServerName = %q, expected %q", result.ServerName, tt.expected.ServerName)
			}
			if result.Version != tt.expected.Version {
				t.Errorf("Version = %q, expected %q", result.Version, tt.expected.Version)
			}
			if result.ServerType != tt.expected.ServerType {
				t.Errorf("ServerType = %q, expected %q", result.ServerType, tt.expected.ServerType)
			}
		})
	}
}

// Test CPE generation
func TestBuildDB2CPE(t *testing.T) {
	tests := []struct {
		version  string
		expected string
	}{
		{"11.5.6.0", "cpe:2.3:a:ibm:db2:11.5.6.0:*:*:*:*:*:*:*"},
		{"10.5.0", "cpe:2.3:a:ibm:db2:10.5.0:*:*:*:*:*:*:*"},
		{"", "cpe:2.3:a:ibm:db2:*:*:*:*:*:*:*:*"}, // Unknown version
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			result := buildDB2CPE(tt.version)
			if result != tt.expected {
				t.Errorf("buildDB2CPE(%q) = %q, expected %q", tt.version, result, tt.expected)
			}
		})
	}
}

// Helper function to build test EXCSATRD response with parameters
func buildTestEXCSATRD(params map[uint16][]byte) []byte {
	// Start with DDM header
	msg := make([]byte, 10)
	msg[2] = DDM_MAGIC
	msg[3] = 0x02 // Format
	binary.BigEndian.PutUint16(msg[4:6], EXCSATRD)
	binary.BigEndian.PutUint16(msg[6:8], 1) // Correlation ID

	// Add parameters
	for codepoint, data := range params {
		paramLen := uint16(4 + len(data)) // 2 (length) + 2 (codepoint) + data
		paramBytes := make([]byte, paramLen)
		binary.BigEndian.PutUint16(paramBytes[0:2], paramLen)
		binary.BigEndian.PutUint16(paramBytes[2:4], codepoint)
		copy(paramBytes[4:], data)
		msg = append(msg, paramBytes...)
	}

	// Update length fields
	totalLen := uint16(len(msg))
	binary.BigEndian.PutUint16(msg[0:2], totalLen)
	binary.BigEndian.PutUint16(msg[8:10], totalLen-6) // Length2

	return msg
}
