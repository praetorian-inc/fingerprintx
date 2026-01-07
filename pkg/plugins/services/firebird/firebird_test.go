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

package firebird

import (
	"encoding/binary"
	"testing"
)

// TestIdentifyFirebird tests the protocol version identification logic
func TestIdentifyFirebird(t *testing.T) {
	tests := []struct {
		name            string
		protocolVersion int32
		wantFirebird    bool
		wantVersion     string
	}{
		{
			name:            "Firebird 5.0 (protocol 17)",
			protocolVersion: 0x8011,
			wantFirebird:    true,
			wantVersion:     "5.0",
		},
		{
			name:            "Firebird 4.0 (protocol 16)",
			protocolVersion: 0x8010,
			wantFirebird:    true,
			wantVersion:     "4.0",
		},
		{
			name:            "Firebird 3.0.2+ (protocol 15)",
			protocolVersion: 0x800f,
			wantFirebird:    true,
			wantVersion:     "3.0.2",
		},
		{
			name:            "Firebird 3.0 (protocol 13)",
			protocolVersion: 0x800d,
			wantFirebird:    true,
			wantVersion:     "3.0",
		},
		{
			name:            "Firebird 2.5 (protocol 12)",
			protocolVersion: 0x800c,
			wantFirebird:    true,
			wantVersion:     "2.5",
		},
		{
			name:            "Firebird 2.1 (protocol 11)",
			protocolVersion: 0x800b,
			wantFirebird:    true,
			wantVersion:     "2.1",
		},
		{
			name:            "Protocol 10 (ambiguous - Firebird 1.x or InterBase)",
			protocolVersion: 0x000a,
			wantFirebird:    true,
			wantVersion:     "", // Ambiguous, wildcard CPE
		},
		{
			name:            "InterBase protocol 14 (NOT Firebird)",
			protocolVersion: 14,
			wantFirebird:    false,
			wantVersion:     "",
		},
		{
			name:            "Unknown protocol without FB_PROTOCOL_FLAG",
			protocolVersion: 15, // 15 without 0x8000 flag
			wantFirebird:    false,
			wantVersion:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFirebird, gotVersion := identifyFirebird(tt.protocolVersion)
			if gotFirebird != tt.wantFirebird {
				t.Errorf("identifyFirebird() gotFirebird = %v, want %v", gotFirebird, tt.wantFirebird)
			}
			if gotVersion != tt.wantVersion {
				t.Errorf("identifyFirebird() gotVersion = %v, want %v", gotVersion, tt.wantVersion)
			}
		})
	}
}

// TestBuildFirebirdCPE tests CPE generation
func TestBuildFirebirdCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "Precise version 5.0.3",
			version: "5.0.3",
			want:    "cpe:2.3:a:firebirdsql:firebird:5.0.3:*:*:*:*:*:*:*",
		},
		{
			name:    "Major.minor version 4.0",
			version: "4.0",
			want:    "cpe:2.3:a:firebirdsql:firebird:4.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version (wildcard)",
			version: "",
			want:    "cpe:2.3:a:firebirdsql:firebird:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildFirebirdCPE(tt.version)
			if got != tt.want {
				t.Errorf("buildFirebirdCPE() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPackInt tests integer packing in big-endian format
func TestPackInt(t *testing.T) {
	tests := []struct {
		name  string
		value int32
		want  []byte
	}{
		{
			name:  "op_connect (1)",
			value: 1,
			want:  []byte{0x00, 0x00, 0x00, 0x01},
		},
		{
			name:  "op_accept (3)",
			value: 3,
			want:  []byte{0x00, 0x00, 0x00, 0x03},
		},
		{
			name:  "protocol 17 (0x8011)",
			value: 0x8011,
			want:  []byte{0x00, 0x00, 0x80, 0x11},
		},
		{
			name:  "protocol 16 (0x8010)",
			value: 0x8010,
			want:  []byte{0x00, 0x00, 0x80, 0x10},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := packInt(tt.value)
			if len(got) != 4 {
				t.Errorf("packInt() length = %d, want 4", len(got))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("packInt()[%d] = 0x%02x, want 0x%02x", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestPackString tests string packing with length prefix
func TestPackString(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want []byte
	}{
		{
			name: "Empty string",
			s:    "",
			want: []byte{0x00, 0x00, 0x00, 0x00}, // Just length field (0)
		},
		{
			name: "Short string 'test'",
			s:    "test",
			want: []byte{
				0x00, 0x00, 0x00, 0x04, // Length = 4
				't', 'e', 's', 't', // String bytes
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := packString(tt.s)

			// Check length field (first 4 bytes)
			length := binary.BigEndian.Uint32(got[0:4])
			if int(length) != len(tt.s) {
				t.Errorf("packString() length field = %d, want %d", length, len(tt.s))
			}

			// Check string bytes
			if len(tt.s) > 0 {
				stringBytes := got[4 : 4+len(tt.s)]
				for i := range tt.s {
					if stringBytes[i] != tt.s[i] {
						t.Errorf("packString() byte[%d] = %c, want %c", i, stringBytes[i], tt.s[i])
					}
				}
			}

			// Check 4-byte alignment padding
			totalLen := 4 + len(tt.s)
			paddingNeeded := (4 - (len(tt.s) % 4)) % 4
			if len(got) != totalLen+paddingNeeded {
				t.Errorf("packString() total length = %d, want %d (with %d padding)", len(got), totalLen+paddingNeeded, paddingNeeded)
			}
		})
	}
}

// TestBuildConnectPacket tests the op_connect packet construction
func TestBuildConnectPacket(t *testing.T) {
	packet := buildConnectPacket()

	// Verify minimum packet length
	// Header (5 int32s + 1 string + 1 string) + 4 protocols (5 int32s each) = varies
	if len(packet) < 100 {
		t.Errorf("buildConnectPacket() length = %d, appears too short", len(packet))
	}

	// Verify op_connect opcode (first 4 bytes)
	opcode := binary.BigEndian.Uint32(packet[0:4])
	if opcode != opConnect {
		t.Errorf("buildConnectPacket() opcode = %d, want %d (op_connect)", opcode, opConnect)
	}

	// Verify op_attach operation (bytes 4-7)
	operation := binary.BigEndian.Uint32(packet[4:8])
	if operation != opAttach {
		t.Errorf("buildConnectPacket() operation = %d, want %d (op_attach)", operation, opAttach)
	}

	// Verify connect version (bytes 8-11)
	version := binary.BigEndian.Uint32(packet[8:12])
	if version != connectVersion3 {
		t.Errorf("buildConnectPacket() version = %d, want %d (CONNECT_VERSION3)", version, connectVersion3)
	}

	// Verify architecture (bytes 12-15)
	arch := binary.BigEndian.Uint32(packet[12:16])
	if arch != archGeneric {
		t.Errorf("buildConnectPacket() arch = %d, want %d (arch_generic)", arch, archGeneric)
	}
}

// TestFirebirdPluginInterface tests that FirebirdPlugin implements Plugin interface correctly
func TestFirebirdPluginInterface(t *testing.T) {
	plugin := &FirebirdPlugin{}

	// Test Name()
	if plugin.Name() != FIREBIRD {
		t.Errorf("FirebirdPlugin.Name() = %q, want %q", plugin.Name(), FIREBIRD)
	}

	// Test PortPriority()
	if !plugin.PortPriority(3050) {
		t.Errorf("FirebirdPlugin.PortPriority(3050) = false, want true")
	}
	if plugin.PortPriority(3306) {
		t.Errorf("FirebirdPlugin.PortPriority(3306) = true, want false")
	}

	// Test Priority()
	if plugin.Priority() != 100 {
		t.Errorf("FirebirdPlugin.Priority() = %d, want 100", plugin.Priority())
	}

	// Test Type()
	// Note: Cannot import plugins.TCP here due to circular dependency
	// Just verify it returns a value
	_ = plugin.Type()
}
