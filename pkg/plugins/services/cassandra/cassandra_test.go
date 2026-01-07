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

package cassandra

import (
	"encoding/binary"
	"testing"
)

// TestBuildOPTIONSFrame tests OPTIONS frame construction
func TestBuildOPTIONSFrame(t *testing.T) {
	frame := buildOPTIONSFrame()

	// Expected frame: [version|flags|stream|opcode|length]
	//                 [0x04   |0x00 |0x0000|0x05  |0x00000000]
	expectedLength := 9
	if len(frame) != expectedLength {
		t.Errorf("buildOPTIONSFrame() length = %d, want %d", len(frame), expectedLength)
	}

	// Verify version byte
	if frame[0] != PROTOCOL_V4_REQUEST {
		t.Errorf("buildOPTIONSFrame() version = 0x%02x, want 0x%02x", frame[0], PROTOCOL_V4_REQUEST)
	}

	// Verify flags byte
	if frame[1] != 0x00 {
		t.Errorf("buildOPTIONSFrame() flags = 0x%02x, want 0x00", frame[1])
	}

	// Verify stream ID (big-endian uint16)
	stream := binary.BigEndian.Uint16(frame[2:4])
	if stream != 0 {
		t.Errorf("buildOPTIONSFrame() stream = %d, want 0", stream)
	}

	// Verify opcode
	if frame[4] != OP_OPTIONS {
		t.Errorf("buildOPTIONSFrame() opcode = 0x%02x, want 0x%02x (OP_OPTIONS)", frame[4], OP_OPTIONS)
	}

	// Verify length field (big-endian uint32)
	length := binary.BigEndian.Uint32(frame[5:9])
	if length != 0 {
		t.Errorf("buildOPTIONSFrame() body length = %d, want 0", length)
	}
}

// TestIsCassandraSUPPORTED tests SUPPORTED response validation
func TestIsCassandraSUPPORTED(t *testing.T) {
	tests := []struct {
		name          string
		response      []byte
		requestStream uint16
		wantValid     bool
		wantErr       bool
	}{
		{
			name: "valid SUPPORTED response v4",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V4_RESPONSE)     // version: 0x84
				resp = append(resp, 0x00)                     // flags
				resp = append(resp, 0x00, 0x00)               // stream: 0
				resp = append(resp, OP_SUPPORTED)             // opcode: 0x06
				// Body: minimal multimap with 1 entry (key "A", empty value list)
				// Body length: 2 (n) + 2 (key len) + 1 (key) + 2 (value count) = 7 bytes
				resp = append(resp, 0x00, 0x00, 0x00, 0x07)
				resp = append(resp, 0x00, 0x01)               // n=1
				resp = append(resp, 0x00, 0x01)               // key length: 1
				resp = append(resp, byte('A'))                // key: "A"
				resp = append(resp, 0x00, 0x00)               // value count: 0
				return resp
			}(),
			requestStream: 0,
			wantValid:     true,
			wantErr:       false,
		},
		{
			name: "valid SUPPORTED response v5",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V5_RESPONSE)     // version: 0x85
				resp = append(resp, 0x00)                     // flags
				resp = append(resp, 0x00, 0x01)               // stream: 1
				resp = append(resp, OP_SUPPORTED)             // opcode: 0x06
				resp = append(resp, 0x00, 0x00, 0x00, 0x07)   // length: 7
				resp = append(resp, 0x00, 0x01)               // n=1
				resp = append(resp, 0x00, 0x01)               // key length: 1
				resp = append(resp, byte('A'))                // key: "A"
				resp = append(resp, 0x00, 0x00)               // value count: 0
				return resp
			}(),
			requestStream: 1,
			wantValid:     true,
			wantErr:       false,
		},
		{
			name: "valid SUPPORTED response v6",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V6_RESPONSE)     // version: 0x86
				resp = append(resp, 0x00)                     // flags
				resp = append(resp, 0x00, 0x00)               // stream: 0
				resp = append(resp, OP_SUPPORTED)             // opcode: 0x06
				resp = append(resp, 0x00, 0x00, 0x00, 0x07)   // length: 7
				resp = append(resp, 0x00, 0x01)               // n=1
				resp = append(resp, 0x00, 0x01)               // key length: 1
				resp = append(resp, byte('A'))                // key: "A"
				resp = append(resp, 0x00, 0x00)               // value count: 0
				return resp
			}(),
			requestStream: 0,
			wantValid:     true,
			wantErr:       false,
		},
		{
			name:          "response too short (header truncated)",
			response:      []byte{0x84, 0x00, 0x00},
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
		{
			name:          "response minimum length (missing body)",
			response:      []byte{0x84, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x05, 0x00},
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
		{
			name: "invalid version byte (request instead of response)",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V4_REQUEST)      // 0x04 (should be 0x84)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x00, 0x00, 0x00, 0x05)
				resp = append(resp, 0x00, 0x00)
				return resp
			}(),
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
		{
			name: "invalid version byte (too high)",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, 0x87)                     // Invalid version
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x00, 0x00, 0x00, 0x05)
				resp = append(resp, 0x00, 0x00)
				return resp
			}(),
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
		{
			name: "stream mismatch",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V4_RESPONSE)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x05)               // stream: 5 (should be 0)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x00, 0x00, 0x00, 0x05)
				resp = append(resp, 0x00, 0x00)
				return resp
			}(),
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
		{
			name: "wrong opcode (OPTIONS instead of SUPPORTED)",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V4_RESPONSE)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_OPTIONS)               // 0x05 (should be 0x06)
				resp = append(resp, 0x00, 0x00, 0x00, 0x05)
				resp = append(resp, 0x00, 0x00)
				return resp
			}(),
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
		{
			name: "length field too small",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V4_RESPONSE)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x00, 0x00, 0x00, 0x02)   // length: 2 (< 5)
				resp = append(resp, 0x00, 0x00)
				return resp
			}(),
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
		{
			name: "length field too large (1MB+)",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V4_RESPONSE)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x01, 0x00, 0x00, 0x01)   // length: 16MB+
				resp = append(resp, 0x00, 0x00)
				return resp
			}(),
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
		{
			name: "response shorter than declared length",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V4_RESPONSE)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x00, 0x00, 0x00, 0x64)   // length: 100 bytes
				resp = append(resp, 0x00, 0x00)               // Only 2 bytes of body
				return resp
			}(),
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := isCassandraSUPPORTED(tt.response, tt.requestStream)
			if valid != tt.wantValid {
				t.Errorf("isCassandraSUPPORTED() valid = %v, want %v", valid, tt.wantValid)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("isCassandraSUPPORTED() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// buildValidSUPPORTEDFrame constructs a valid SUPPORTED response frame with given multimap
func buildValidSUPPORTEDFrame(multimap map[string][]string) []byte {
	resp := make([]byte, 0, 512)

	// Calculate body first to know total length
	body := make([]byte, 0, 512)

	// Number of entries
	numEntries := uint16(len(multimap))
	entriesBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(entriesBuf, numEntries)
	body = append(body, entriesBuf...)

	// Encode each key-value pair
	for key, values := range multimap {
		// Encode key (CQL [string])
		keyLen := uint16(len(key))
		keyLenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(keyLenBuf, keyLen)
		body = append(body, keyLenBuf...)
		body = append(body, []byte(key)...)

		// Encode value list (CQL [string list])
		numValues := uint16(len(values))
		numValuesBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(numValuesBuf, numValues)
		body = append(body, numValuesBuf...)

		for _, val := range values {
			valLen := uint16(len(val))
			valLenBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(valLenBuf, valLen)
			body = append(body, valLenBuf...)
			body = append(body, []byte(val)...)
		}
	}

	// Build header
	resp = append(resp, PROTOCOL_V4_RESPONSE)            // version
	resp = append(resp, 0x00)                            // flags
	resp = append(resp, 0x00, 0x00)                      // stream
	resp = append(resp, OP_SUPPORTED)                    // opcode

	// Body length (big-endian uint32)
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(body)))
	resp = append(resp, lengthBuf...)

	// Body
	resp = append(resp, body...)

	return resp
}

// TestParseSUPPORTEDMultimap tests multimap parsing with real byte sequences
func TestParseSUPPORTEDMultimap(t *testing.T) {
	tests := []struct {
		name          string
		response      []byte
		wantMultimap  map[string][]string
		wantErr       bool
	}{
		{
			name: "empty multimap",
			response: buildValidSUPPORTEDFrame(map[string][]string{}),
			wantMultimap: map[string][]string{},
			wantErr:      false,
		},
		{
			name: "single key with single value",
			response: buildValidSUPPORTEDFrame(map[string][]string{
				"CQL_VERSION": {"3.4.7"},
			}),
			wantMultimap: map[string][]string{
				"CQL_VERSION": {"3.4.7"},
			},
			wantErr: false,
		},
		{
			name: "single key with multiple values",
			response: buildValidSUPPORTEDFrame(map[string][]string{
				"COMPRESSION": {"lz4", "snappy", "zstd"},
			}),
			wantMultimap: map[string][]string{
				"COMPRESSION": {"lz4", "snappy", "zstd"},
			},
			wantErr: false,
		},
		{
			name: "multiple keys with mixed values (Cassandra 5.0)",
			response: buildValidSUPPORTEDFrame(map[string][]string{
				"CQL_VERSION":       {"3.4.7"},
				"COMPRESSION":       {"lz4", "snappy", "zstd"},
				"PROTOCOL_VERSIONS": {"4/v4", "5/v5", "6/v6"},
			}),
			wantMultimap: map[string][]string{
				"CQL_VERSION":       {"3.4.7"},
				"COMPRESSION":       {"lz4", "snappy", "zstd"},
				"PROTOCOL_VERSIONS": {"4/v4", "5/v5", "6/v6"},
			},
			wantErr: false,
		},
		{
			name: "Cassandra 4.0 markers",
			response: buildValidSUPPORTEDFrame(map[string][]string{
				"CQL_VERSION":       {"3.4.5"},
				"COMPRESSION":       {"lz4", "snappy", "zstd"},
				"PROTOCOL_VERSIONS": {"3/v3", "4/v4", "5/v5"},
			}),
			wantMultimap: map[string][]string{
				"CQL_VERSION":       {"3.4.5"},
				"COMPRESSION":       {"lz4", "snappy", "zstd"},
				"PROTOCOL_VERSIONS": {"3/v3", "4/v4", "5/v5"},
			},
			wantErr: false,
		},
		{
			name: "Cassandra 3.11 markers",
			response: buildValidSUPPORTEDFrame(map[string][]string{
				"CQL_VERSION":       {"3.4.4"},
				"COMPRESSION":       {"lz4", "snappy"},
				"PROTOCOL_VERSIONS": {"3/v3", "4/v4"},
			}),
			wantMultimap: map[string][]string{
				"CQL_VERSION":       {"3.4.4"},
				"COMPRESSION":       {"lz4", "snappy"},
				"PROTOCOL_VERSIONS": {"3/v3", "4/v4"},
			},
			wantErr: false,
		},
		{
			name: "ScyllaDB markers",
			response: buildValidSUPPORTEDFrame(map[string][]string{
				"CQL_VERSION":       {"3.3.1"},
				"SCYLLA_SHARD":      {"0"},
				"SCYLLA_NR_SHARDS":  {"4"},
				"SCYLLA_SHARDING_ALGORITHM": {"biased-token-round-robin"},
			}),
			wantMultimap: map[string][]string{
				"CQL_VERSION":       {"3.3.1"},
				"SCYLLA_SHARD":      {"0"},
				"SCYLLA_NR_SHARDS":  {"4"},
				"SCYLLA_SHARDING_ALGORITHM": {"biased-token-round-robin"},
			},
			wantErr: false,
		},
		{
			name:         "response too short (no header)",
			response:     []byte{0x84, 0x00},
			wantMultimap: nil,
			wantErr:      true,
		},
		{
			name: "body too short (no entry count)",
			response: func() []byte {
				resp := make([]byte, 0, 20)
				resp = append(resp, PROTOCOL_V4_RESPONSE)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x00, 0x00, 0x00, 0x01) // length: 1
				resp = append(resp, 0x00)                   // Only 1 byte of body
				return resp
			}(),
			wantMultimap: nil,
			wantErr:      true,
		},
		{
			name: "truncated string key",
			response: func() []byte {
				resp := make([]byte, 0, 30)
				resp = append(resp, PROTOCOL_V4_RESPONSE)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x00, 0x00, 0x00, 0x04) // length: 4
				resp = append(resp, 0x00, 0x01)             // n=1
				resp = append(resp, 0x00, 0x0A)             // key length: 10 bytes (truncated)
				return resp
			}(),
			wantMultimap: nil,
			wantErr:      true,
		},
		{
			name: "truncated string list count",
			response: func() []byte {
				resp := make([]byte, 0, 50)
				resp = append(resp, PROTOCOL_V4_RESPONSE)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x00, 0x00, 0x00, 0x08) // length: 8
				resp = append(resp, 0x00, 0x01)             // n=1
				resp = append(resp, 0x00, 0x03)             // key length: 3
				resp = append(resp, []byte("FOO")...)       // key: "FOO"
				// Missing value list count
				return resp
			}(),
			wantMultimap: nil,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			multimap, err := parseSUPPORTEDMultimap(tt.response)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseSUPPORTEDMultimap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Compare multimap lengths
			if len(multimap) != len(tt.wantMultimap) {
				t.Errorf("parseSUPPORTEDMultimap() got %d keys, want %d keys", len(multimap), len(tt.wantMultimap))
			}

			// Compare each key-value pair
			for key, wantValues := range tt.wantMultimap {
				gotValues, ok := multimap[key]
				if !ok {
					t.Errorf("parseSUPPORTEDMultimap() missing key %q", key)
					continue
				}

				if len(gotValues) != len(wantValues) {
					t.Errorf("parseSUPPORTEDMultimap() key %q: got %d values, want %d values", key, len(gotValues), len(wantValues))
					continue
				}

				for i := range wantValues {
					if gotValues[i] != wantValues[i] {
						t.Errorf("parseSUPPORTEDMultimap() key %q value[%d]: got %q, want %q", key, i, gotValues[i], wantValues[i])
					}
				}
			}
		})
	}
}

// TestExtractCassandraVersion tests version detection from SUPPORTED multimap markers
func TestExtractCassandraVersion(t *testing.T) {
	tests := []struct {
		name           string
		multimap       map[string][]string
		wantProduct    string
		wantVersion    string
		wantConfidence string
	}{
		{
			name: "Cassandra 5.0 (CQL 3.4.7)",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.4.7"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "5.0",
			wantConfidence: "high",
		},
		{
			name: "Cassandra 4.1 (CQL 3.4.6)",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.4.6"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "4.1",
			wantConfidence: "high",
		},
		{
			name: "Cassandra 4.0 (CQL 3.4.5)",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.4.5"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "4.0",
			wantConfidence: "high",
		},
		{
			name: "Cassandra 3.11 (CQL 3.4.4)",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.4.4"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "3.11",
			wantConfidence: "high",
		},
		{
			name: "Cassandra 2.2 (CQL 3.3.x)",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.3.1"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "2.2",
			wantConfidence: "medium",
		},
		{
			name: "Cassandra 2.1 (CQL 3.2.x)",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.2.0"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "2.1",
			wantConfidence: "medium",
		},
		{
			name: "Protocol v6 fallback (no CQL_VERSION)",
			multimap: map[string][]string{
				"PROTOCOL_VERSIONS": {"3/v3", "4/v4", "5/v5", "6/v6"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "5.0+",
			wantConfidence: "high",
		},
		{
			name: "Protocol v5 fallback (no CQL_VERSION)",
			multimap: map[string][]string{
				"PROTOCOL_VERSIONS": {"3/v3", "4/v4", "5/v5"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "4.0+",
			wantConfidence: "medium",
		},
		{
			name: "Protocol v4 only (no v5, no CQL_VERSION)",
			multimap: map[string][]string{
				"PROTOCOL_VERSIONS": {"3/v3", "4/v4"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "2.2-3.x",
			wantConfidence: "medium",
		},
		{
			name: "Protocol v3 only (no v4, no CQL_VERSION)",
			multimap: map[string][]string{
				"PROTOCOL_VERSIONS": {"3/v3"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "2.1.x",
			wantConfidence: "medium",
		},
		{
			name: "Zstd compression marker (fallback version)",
			multimap: map[string][]string{
				"COMPRESSION": {"lz4", "snappy", "zstd"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "4.0+",
			wantConfidence: "high",
		},
		{
			name: "No zstd compression (older version)",
			multimap: map[string][]string{
				"COMPRESSION": {"lz4", "snappy"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "",
			wantConfidence: "low",
		},
		{
			name: "ScyllaDB detection",
			multimap: map[string][]string{
				"CQL_VERSION":  {"3.3.1"},
				"SCYLLA_SHARD": {"0"},
			},
			wantProduct:    "ScyllaDB",
			wantVersion:    "2.2",
			wantConfidence: "medium",
		},
		{
			name: "DataStax Enterprise detection",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.4.5"},
				"DSE_VERSION": {"6.8.0"},
			},
			wantProduct:    "DataStax Enterprise",
			wantVersion:    "4.0",
			wantConfidence: "high",
		},
		{
			name: "Empty multimap (no markers)",
			multimap: map[string][]string{},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "",
			wantConfidence: "low",
		},
		{
			name: "Unknown CQL version with zstd (trust zstd)",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.5.0"},
				"COMPRESSION": {"lz4", "snappy", "zstd"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "4.0+",
			wantConfidence: "high",
		},
		{
			name: "CQL 3.4.x unknown minor (medium confidence)",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.4.99"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "3.*",
			wantConfidence: "medium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := extractCassandraVersion(tt.multimap)

			if metadata.Product != tt.wantProduct {
				t.Errorf("extractCassandraVersion() product = %q, want %q", metadata.Product, tt.wantProduct)
			}

			if metadata.Version != tt.wantVersion {
				t.Errorf("extractCassandraVersion() version = %q, want %q", metadata.Version, tt.wantVersion)
			}

			if metadata.Confidence != tt.wantConfidence {
				t.Errorf("extractCassandraVersion() confidence = %q, want %q", metadata.Confidence, tt.wantConfidence)
			}
		})
	}
}

// TestBuildCassandraCPE tests CPE generation for Cassandra/ScyllaDB/DSE
func TestBuildCassandraCPE(t *testing.T) {
	tests := []struct {
		name        string
		product     string
		version     string
		wantCPE     string
	}{
		// Apache Cassandra CPEs
		{
			name:    "Cassandra 5.0",
			product: "Apache Cassandra",
			version: "5.0",
			wantCPE: "cpe:2.3:a:apache:cassandra:5.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Cassandra 4.1",
			product: "Apache Cassandra",
			version: "4.1",
			wantCPE: "cpe:2.3:a:apache:cassandra:4.1:*:*:*:*:*:*:*",
		},
		{
			name:    "Cassandra 4.0",
			product: "Apache Cassandra",
			version: "4.0",
			wantCPE: "cpe:2.3:a:apache:cassandra:4.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Cassandra 3.11",
			product: "Apache Cassandra",
			version: "3.11",
			wantCPE: "cpe:2.3:a:apache:cassandra:3.11:*:*:*:*:*:*:*",
		},
		{
			name:    "Cassandra 2.2",
			product: "Apache Cassandra",
			version: "2.2",
			wantCPE: "cpe:2.3:a:apache:cassandra:2.2:*:*:*:*:*:*:*",
		},
		{
			name:    "Cassandra unknown version (wildcard)",
			product: "Apache Cassandra",
			version: "",
			wantCPE: "cpe:2.3:a:apache:cassandra:*:*:*:*:*:*:*:*",
		},
		{
			name:    "Cassandra empty product defaults to Apache",
			product: "",
			version: "4.0",
			wantCPE: "cpe:2.3:a:apache:cassandra:4.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Cassandra version range (4.0+)",
			product: "Apache Cassandra",
			version: "4.0+",
			wantCPE: "cpe:2.3:a:apache:cassandra:4.0+:*:*:*:*:*:*:*",
		},

		// ScyllaDB CPEs
		{
			name:    "ScyllaDB with version",
			product: "ScyllaDB",
			version: "5.2",
			wantCPE: "cpe:2.3:a:scylladb:scylla:5.2:*:*:*:*:*:*:*",
		},
		{
			name:    "ScyllaDB unknown version",
			product: "ScyllaDB",
			version: "",
			wantCPE: "cpe:2.3:a:scylladb:scylla:*:*:*:*:*:*:*:*",
		},

		// DataStax Enterprise CPEs
		{
			name:    "DSE with version",
			product: "DataStax Enterprise",
			version: "6.8",
			wantCPE: "cpe:2.3:a:datastax:datastax_enterprise:6.8:*:*:*:*:*:*:*",
		},
		{
			name:    "DSE unknown version",
			product: "DataStax Enterprise",
			version: "",
			wantCPE: "cpe:2.3:a:datastax:datastax_enterprise:*:*:*:*:*:*:*:*",
		},

		// Unknown product fallback
		{
			name:    "Unknown product falls back to Cassandra",
			product: "Unknown Product",
			version: "1.0",
			wantCPE: "cpe:2.3:a:apache:cassandra:1.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildCassandraCPE(tt.product, tt.version)
			if cpe != tt.wantCPE {
				t.Errorf("buildCassandraCPE(%q, %q) = %q, want %q", tt.product, tt.version, cpe, tt.wantCPE)
			}
		})
	}
}
