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

package neo4j

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildBoltHandshake(t *testing.T) {
	handshake := buildBoltHandshake()

	// Should be 20 bytes
	assert.Len(t, handshake, 20)

	// Check magic bytes
	assert.Equal(t, byte(0x60), handshake[0])
	assert.Equal(t, byte(0x60), handshake[1])
	assert.Equal(t, byte(0xB0), handshake[2])
	assert.Equal(t, byte(0x17), handshake[3])

	// Check version 4.4 is first
	assert.Equal(t, byte(0x00), handshake[4])
	assert.Equal(t, byte(0x00), handshake[5])
	assert.Equal(t, byte(0x04), handshake[6])
	assert.Equal(t, byte(0x04), handshake[7])
}

func TestBuildHelloMessage(t *testing.T) {
	msg := buildHelloMessage()

	// Should have chunk header (2 bytes) + body + terminator (2 bytes)
	assert.Greater(t, len(msg), 4)

	// Check chunk terminator
	assert.Equal(t, byte(0x00), msg[len(msg)-2])
	assert.Equal(t, byte(0x00), msg[len(msg)-1])

	// Check structure marker (B1) and HELLO tag (01)
	// After 2-byte chunk header
	assert.Equal(t, byte(0xB1), msg[2])
	assert.Equal(t, byte(0x01), msg[3])
}

func TestCheckBoltHandshakeResponse(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		want     bool
		wantErr  bool
	}{
		{
			name:     "valid version 4.4",
			response: []byte{0x00, 0x00, 0x04, 0x04},
			want:     true,
			wantErr:  false,
		},
		{
			name:     "valid version 5.0",
			response: []byte{0x00, 0x00, 0x05, 0x00},
			want:     true,
			wantErr:  false,
		},
		{
			name:     "rejected (all zeros)",
			response: []byte{0x00, 0x00, 0x00, 0x00},
			want:     false,
			wantErr:  true,
		},
		{
			name:     "too short",
			response: []byte{0x00, 0x00, 0x04},
			want:     false,
			wantErr:  true,
		},
		{
			name:     "empty",
			response: []byte{},
			want:     false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := checkBoltHandshakeResponse(tt.response)
			assert.Equal(t, tt.want, got)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseNeo4jVersion(t *testing.T) {
	tests := []struct {
		name      string
		serverStr string
		want      string
	}{
		{
			name:      "Neo4j 5.13.0",
			serverStr: "Neo4j/5.13.0",
			want:      "5.13.0",
		},
		{
			name:      "Neo4j 2025.11.2",
			serverStr: "Neo4j/2025.11.2",
			want:      "2025.11.2",
		},
		{
			name:      "Neo4j 4.4.28",
			serverStr: "Neo4j/4.4.28",
			want:      "4.4.28",
		},
		{
			name:      "Neo4j with trailing metadata",
			serverStr: "Neo4j/5.13.0 Community",
			want:      "5.13.0",
		},
		{
			name:      "TuGraph (not Neo4j)",
			serverStr: "TuGraph/3.0.0",
			want:      "",
		},
		{
			name:      "empty string",
			serverStr: "",
			want:      "",
		},
		{
			name:      "no prefix",
			serverStr: "5.13.0",
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseNeo4jVersion(tt.serverStr)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildNeo4jCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "version 5.13.0",
			version: "5.13.0",
			want:    "cpe:2.3:a:neo4j:neo4j:5.13.0:*:*:*:*:*:*:*",
		},
		{
			name:    "version 2025.11.2",
			version: "2025.11.2",
			want:    "cpe:2.3:a:neo4j:neo4j:2025.11.2:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version",
			version: "",
			want:    "",
		},
		{
			name:    "unknown version (auth required)",
			version: "unknown",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildNeo4jCPE(tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestContainsNeo4jErrorCode(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "Neo4j unauthorized error",
			data: []byte("codeNeo.ClientError.Security.Unauthorized"),
			want: true,
		},
		{
			name: "Neo4j general error",
			data: []byte("Neo.DatabaseError.General.Unknown"),
			want: true,
		},
		{
			name: "no Neo4j error",
			data: []byte("some other error message"),
			want: false,
		},
		{
			name: "empty data",
			data: []byte{},
			want: false,
		},
		{
			name: "partial Neo",
			data: []byte("Neo"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsNeo4jErrorCode(tt.data)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractServerField(t *testing.T) {
	// Test data mimicking PackStream encoded map with "server" field
	// Map: A3 (3 entries)
	// Key: 86 "server" (tiny string 6 chars)
	// Value: 8F "Neo4j/2025.11.2" (tiny string 15 chars)
	testData := []byte{
		0xA3,                               // Map with 3 entries
		0x86,                               // Tiny string (6 chars)
		's', 'e', 'r', 'v', 'e', 'r',       // "server"
		0x8F,                               // Tiny string (15 chars)
		'N', 'e', 'o', '4', 'j', '/', '2', '0', '2', '5', '.', '1', '1', '.', '2', // "Neo4j/2025.11.2"
	}

	result := extractServerField(testData)
	assert.Equal(t, "Neo4j/2025.11.2", result)
}

func TestPluginMethods(t *testing.T) {
	plugin := &NEO4JPlugin{}

	t.Run("Name", func(t *testing.T) {
		assert.Equal(t, "neo4j", plugin.Name())
	})

	t.Run("PortPriority", func(t *testing.T) {
		assert.True(t, plugin.PortPriority(7687))
		assert.False(t, plugin.PortPriority(7474))
		assert.False(t, plugin.PortPriority(443))
	})

	t.Run("Priority", func(t *testing.T) {
		// Should run before HTTP (100)
		assert.Less(t, plugin.Priority(), 100)
	})
}

func TestTLSPluginMethods(t *testing.T) {
	plugin := &NEO4JTLSPlugin{}

	t.Run("Name", func(t *testing.T) {
		assert.Equal(t, "neo4j", plugin.Name())
	})

	t.Run("PortPriority", func(t *testing.T) {
		assert.True(t, plugin.PortPriority(7687))
		assert.False(t, plugin.PortPriority(443))
	})

	t.Run("Priority", func(t *testing.T) {
		// Should run before HTTP (100)
		assert.Less(t, plugin.Priority(), 100)
	})
}
