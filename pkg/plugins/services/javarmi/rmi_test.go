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

package javarmi

import (
	"testing"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

// TestIsValidRMIResponse tests the 5-layer validation logic
func TestIsValidRMIResponse(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected bool
		reason   string
	}{
		{
			name: "valid RMI response - JDK 11",
			response: []byte{
				0x4e,       // ProtocolAck
				0x00, 0x0a, // Length: 10
				'1', '7', '2', '.', '1', '8', '.', '0', '.', '1', // "172.18.0.1"
				0x00, 0x00, // Null bytes
				0xfc, 0x64, // Port: 64612
			},
			expected: true,
			reason:   "Valid JRMP response from JDK 11",
		},
		{
			name:     "too short - less than 3 bytes",
			response: []byte{0x4e, 0x00},
			expected: false,
			reason:   "Fails layer 1: minimum length check",
		},
		{
			name: "wrong first byte - not ProtocolAck",
			response: []byte{
				0x4f,       // ProtocolNack instead of Ack
				0x00, 0x0a, // Length
				'1', '7', '2', '.', '1', '8', '.', '0', '.', '1',
			},
			expected: false,
			reason:   "Fails layer 2: not ProtocolAck (0x4E)",
		},
		{
			name: "invalid length - too short",
			response: []byte{
				0x4e,       // ProtocolAck
				0x00, 0x02, // Length: 2 (invalid, too short for hostname)
				'a', 'b',
			},
			expected: false,
			reason:   "Fails layer 3: endpoint length < 3",
		},
		{
			name: "invalid length - too long",
			response: []byte{
				0x4e,       // ProtocolAck
				0x01, 0x00, // Length: 256 (exceeds DNS max 253)
			},
			expected: false,
			reason:   "Fails layer 3: endpoint length > 253",
		},
		{
			name: "response too short for claimed length",
			response: []byte{
				0x4e,       // ProtocolAck
				0x00, 0x0a, // Length: 10
				'1', '2', '3', // Only 3 bytes, claims 10
			},
			expected: false,
			reason:   "Fails layer 4: response shorter than claimed structure",
		},
		{
			name: "non-ASCII characters in endpoint",
			response: []byte{
				0x4e,       // ProtocolAck
				0x00, 0x05, // Length: 5
				0xFF, 0xFE, 0xFD, 0xFC, 0xFB, // Non-ASCII bytes
				0x00, 0x00, // Nulls
				0x00, 0x50, // Port
			},
			expected: false,
			reason:   "Fails layer 5: endpoint contains non-printable characters",
		},
		{
			name: "valid response with extra data",
			response: []byte{
				0x4e,       // ProtocolAck
				0x00, 0x09, // Length: 9
				'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', // "localhost"
				0x00, 0x00, // Nulls
				0x04, 0x4b, // Port: 1099
				0x01, 0x02, 0x03, // Extra endpoint data (allowed by spec)
			},
			expected: true,
			reason:   "Valid response with additional endpoint data",
		},
		{
			name: "minimum valid response",
			response: []byte{
				0x4e,       // ProtocolAck
				0x00, 0x03, // Length: 3
				'1', '.', '2', // "1.2" (minimum valid)
				0x00, 0x00, // Nulls
				0x04, 0x4b, // Port
			},
			expected: true,
			reason:   "Minimum valid response (3-char endpoint)",
		},
		{
			name: "valid IPv6 endpoint",
			response: []byte{
				0x4e,       // ProtocolAck
				0x00, 0x03, // Length: 3
				':', ':', '1', // "::1"
				0x00, 0x00, // Nulls
				0x04, 0x4b, // Port
			},
			expected: true,
			reason:   "Valid IPv6 loopback address",
		},
		{
			name:     "empty response",
			response: []byte{},
			expected: false,
			reason:   "Fails layer 1: empty response",
		},
		{
			name: "random data - coincidental 0x4e",
			response: []byte{
				0x4e,       // Coincidentally starts with 0x4e
				0xFF, 0xFF, // Invalid length (65535)
				0x01, 0x02, 0x03, 0x04, // Random data
			},
			expected: false,
			reason:   "Fails layer 3: length field is unreasonable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidRMIResponse(tt.response)
			if result != tt.expected {
				t.Errorf("%s: expected %v, got %v. Reason: %s",
					tt.name, tt.expected, result, tt.reason)
			}
		})
	}
}

// TestExtractEndpoint tests endpoint parsing logic
func TestExtractEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name: "valid endpoint with port",
			data: []byte{
				0x00, 0x0a, // Length: 10
				'1', '7', '2', '.', '1', '8', '.', '0', '.', '1', // "172.18.0.1"
				0x00, 0x00, // Nulls
				0xfc, 0x64, // Port: 64612
			},
			expected: "172.18.0.1:64612",
		},
		{
			name: "localhost endpoint",
			data: []byte{
				0x00, 0x09, // Length: 9
				'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', // "localhost"
				0x00, 0x00, // Nulls
				0x04, 0x4b, // Port: 1099
			},
			expected: "localhost:1099",
		},
		{
			name: "IPv6 loopback",
			data: []byte{
				0x00, 0x03, // Length: 3
				':', ':', '1', // "::1"
				0x00, 0x00, // Nulls
				0x04, 0x4b, // Port: 1099
			},
			expected: "::1:1099",
		},
		{
			name: "hostname only - no port data",
			data: []byte{
				0x00, 0x04, // Length: 4
				't', 'e', 's', 't', // "test"
			},
			expected: "test",
		},
		{
			name:     "too short - no length field",
			data:     []byte{0x00},
			expected: "",
		},
		{
			name: "claimed length exceeds actual data",
			data: []byte{
				0x00, 0x14, // Length: 20
				't', 'e', 's', 't', // Only 4 bytes
			},
			expected: "",
		},
		{
			name:     "empty data",
			data:     []byte{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractEndpoint(tt.data)
			if result != tt.expected {
				t.Errorf("%s: expected %q, got %q", tt.name, tt.expected, result)
			}
		})
	}
}

// TestRMIPlugin validates the plugin interface implementation
func TestRMIPlugin(t *testing.T) {
	plugin := &RMIPlugin{}

	// Test Name
	if plugin.Name() != "java-rmi" {
		t.Errorf("Name(): expected %q, got %q", "java-rmi", plugin.Name())
	}

	// Test Type
	if plugin.Type() != plugins.TCP {
		t.Errorf("Type(): expected TCP, got %v", plugin.Type())
	}

	// Test Priority
	if plugin.Priority() != 500 {
		t.Errorf("Priority(): expected 500, got %d", plugin.Priority())
	}

	// Test PortPriority
	testPorts := []struct {
		port     uint16
		expected bool
	}{
		{1099, true},  // Standard RMI Registry
		{1098, true},  // Alternative
		{9999, true},  // JMX
		{10000, true}, // Custom range
		{8080, false}, // Not RMI
		{22, false},   // SSH
		{3306, false}, // MySQL
	}

	for _, tp := range testPorts {
		result := plugin.PortPriority(tp.port)
		if result != tp.expected {
			t.Errorf("PortPriority(%d): expected %v, got %v",
				tp.port, tp.expected, result)
		}
	}
}
