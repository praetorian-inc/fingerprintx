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
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildBoltHandshake(t *testing.T) {
	handshake := buildBoltHandshake()

	require.Len(t, handshake, 20, "Bolt handshake must be exactly 20 bytes")

	// Verify magic bytes: 60 60 B0 17
	assert.Equal(t, boltMagic, handshake[0:4], "first 4 bytes must be Bolt magic")

	// Verify version proposals (big-endian: 00 00 MINOR MAJOR)
	expectedVersions := []struct {
		offset int
		major  byte
		minor  byte
		desc   string
	}{
		{4, 6, 0, "Bolt 6.0 (Neo4j 2025.10+)"},
		{8, 5, 0, "Bolt 5.0 (Neo4j 5.x)"},
		{12, 4, 4, "Bolt 4.4 (Neo4j 4.4)"},
		{16, 4, 1, "Bolt 4.1 (Neo4j 4.1+)"},
	}

	for _, v := range expectedVersions {
		assert.Equal(t, []byte{0x00, 0x00, v.minor, v.major}, handshake[v.offset:v.offset+4],
			"version slot at offset %d should be %s", v.offset, v.desc)
	}
}

func TestBuildHelloMessage(t *testing.T) {
	msg := buildHelloMessage()

	require.Greater(t, len(msg), 6, "HELLO message too short")

	// Must end with 00 00 chunk terminator
	assert.Equal(t, []byte{0x00, 0x00}, msg[len(msg)-2:], "must end with chunk terminator")

	// After 2-byte chunk header: B1 (structure marker) 01 (HELLO tag)
	assert.Equal(t, byte(0xB1), msg[2], "structure marker")
	assert.Equal(t, byte(HELLO_SIGNATURE), msg[3], "HELLO signature")

	// Verify user_agent is present in the message
	assert.True(t, bytes.Contains(msg, []byte("user_agent")), "must contain user_agent key")
	assert.True(t, bytes.Contains(msg, []byte("fingerprintx")), "must contain fingerprintx user agent")
}

func TestBuildLogonMessage(t *testing.T) {
	msg := buildLogonMessage()

	require.Greater(t, len(msg), 6, "LOGON message too short")

	// Must end with 00 00 chunk terminator
	assert.Equal(t, []byte{0x00, 0x00}, msg[len(msg)-2:], "must end with chunk terminator")

	// After 2-byte chunk header: B1 (structure marker) 6A (LOGON tag)
	assert.Equal(t, byte(0xB1), msg[2], "structure marker")
	assert.Equal(t, byte(LOGON_SIGNATURE), msg[3], "LOGON signature")

	// Verify auth fields are present
	assert.True(t, bytes.Contains(msg, []byte("scheme")), "must contain scheme")
	assert.True(t, bytes.Contains(msg, []byte("basic")), "must contain basic auth scheme")
}

func TestCheckBoltHandshakeResponse(t *testing.T) {
	proposals := boltHandshakeProposals()

	t.Run("accepts valid Bolt versions", func(t *testing.T) {
		validVersions := []struct {
			response []byte
			expected uint32
			desc     string
		}{
			{[]byte{0x00, 0x00, 0x00, 0x06}, boltVersion(6, 0), "Bolt 6.0"},
			{[]byte{0x00, 0x00, 0x00, 0x05}, boltVersion(5, 0), "Bolt 5.0"},
			{[]byte{0x00, 0x00, 0x04, 0x04}, boltVersion(4, 4), "Bolt 4.4"},
			{[]byte{0x00, 0x00, 0x01, 0x04}, boltVersion(4, 1), "Bolt 4.1"},
		}

		for _, tc := range validVersions {
			sel, ok, err := checkBoltHandshakeResponse(tc.response, proposals)
			assert.True(t, ok, "%s should be accepted", tc.desc)
			assert.NoError(t, err, "%s should not error", tc.desc)
			assert.Equal(t, tc.expected, sel, "%s version mismatch", tc.desc)
		}
	})

	t.Run("rejects zero response (server doesn't speak Bolt)", func(t *testing.T) {
		_, ok, err := checkBoltHandshakeResponse([]byte{0x00, 0x00, 0x00, 0x00}, proposals)
		assert.False(t, ok)
		assert.Error(t, err)
	})

	t.Run("rejects unoffered Bolt versions", func(t *testing.T) {
		// Bolt 7.0 - doesn't exist yet
		_, ok, err := checkBoltHandshakeResponse([]byte{0x00, 0x00, 0x00, 0x07}, proposals)
		assert.False(t, ok)
		assert.Error(t, err)

		// Bolt 3.0 - too old, not in our proposals
		_, ok, err = checkBoltHandshakeResponse([]byte{0x00, 0x00, 0x00, 0x03}, proposals)
		assert.False(t, ok)
		assert.Error(t, err)
	})

	t.Run("rejects malformed responses", func(t *testing.T) {
		malformed := []struct {
			response []byte
			desc     string
		}{
			{[]byte{}, "empty"},
			{[]byte{0x00}, "1 byte"},
			{[]byte{0x00, 0x00}, "2 bytes"},
			{[]byte{0x00, 0x00, 0x04}, "3 bytes"},
		}

		for _, tc := range malformed {
			_, ok, err := checkBoltHandshakeResponse(tc.response, proposals)
			assert.False(t, ok, "%s should be rejected", tc.desc)
			assert.Error(t, err, "%s should error", tc.desc)
		}
	})
}

func TestFalsePositivePrevention(t *testing.T) {
	proposals := boltHandshakeProposals()

	t.Run("HTTP responses don't match Bolt handshake", func(t *testing.T) {
		httpResponses := [][]byte{
			[]byte("HTTP"),                   // HTTP/1.x start
			[]byte("HTTP/1.1 200 OK\r\n"),    // Full HTTP response line
			[]byte("<htm"),                   // HTML start
			[]byte("<!DO"),                   // DOCTYPE
			[]byte("{\"er"),                  // JSON error response
			[]byte("400 "),                   // HTTP error codes
			[]byte("500 "),                   // Server error
			[]byte("\r\n\r\n"),               // Empty headers
			[]byte("Cont"),                   // Content-Type start
			[]byte("Conn"),                   // Connection header
		}

		for _, resp := range httpResponses {
			if len(resp) >= 4 {
				_, ok, _ := checkBoltHandshakeResponse(resp[:4], proposals)
				assert.False(t, ok, "HTTP-like response %q should not match Bolt", resp)
			}
		}
	})

	t.Run("SSH banner doesn't match Bolt handshake", func(t *testing.T) {
		sshBanner := []byte("SSH-2.0-OpenSSH_8.9")
		_, ok, _ := checkBoltHandshakeResponse(sshBanner[:4], proposals)
		assert.False(t, ok, "SSH banner should not match Bolt")
	})

	t.Run("MySQL greeting doesn't match Bolt handshake", func(t *testing.T) {
		mysqlGreeting := []byte{0x4a, 0x00, 0x00, 0x00}
		_, ok, _ := checkBoltHandshakeResponse(mysqlGreeting, proposals)
		assert.False(t, ok, "MySQL greeting should not match Bolt")
	})

	t.Run("PostgreSQL response doesn't match Bolt handshake", func(t *testing.T) {
		pgError := []byte{'E', 0x00, 0x00, 0x00}
		_, ok, _ := checkBoltHandshakeResponse(pgError, proposals)
		assert.False(t, ok, "PostgreSQL response should not match Bolt")
	})

	t.Run("random binary data doesn't match Bolt handshake", func(t *testing.T) {
		randomData := [][]byte{
			{0xFF, 0xFF, 0xFF, 0xFF},
			{0x01, 0x02, 0x03, 0x04},
			{0xDE, 0xAD, 0xBE, 0xEF},
			{0x00, 0x01, 0x02, 0x03},
		}

		for _, data := range randomData {
			_, ok, _ := checkBoltHandshakeResponse(data, proposals)
			assert.False(t, ok, "random data %x should not match Bolt", data)
		}
	})
}

func TestParseHelloResponse(t *testing.T) {
	t.Run("Neo4j SUCCESS with server field", func(t *testing.T) {
		// B1 70 A1 86 "server" 8F "Neo4j/2025.11.2"
		body := []byte{
			0xB1, SUCCESS_SIGNATURE,
			0xA1,
			0x86, 's', 'e', 'r', 'v', 'e', 'r',
			0x8F,
			'N', 'e', 'o', '4', 'j', '/', '2', '0', '2', '5', '.', '1', '1', '.', '2',
		}
		raw := chunkMessage(body)

		serverStr, isNeo4j, err := parseHelloResponse(raw)
		require.NoError(t, err)
		assert.True(t, isNeo4j, "should detect Neo4j")
		assert.Equal(t, "Neo4j/2025.11.2", serverStr)
	})

	t.Run("TuGraph SUCCESS - Bolt but NOT Neo4j", func(t *testing.T) {
		body := []byte{
			0xB1, SUCCESS_SIGNATURE,
			0xA1,
			0x86, 's', 'e', 'r', 'v', 'e', 'r',
			0x8D, // 13 chars
			'T', 'u', 'G', 'r', 'a', 'p', 'h', '/', '3', '.', '0', '.', '0',
		}
		raw := chunkMessage(body)

		serverStr, isNeo4j, err := parseHelloResponse(raw)
		require.NoError(t, err)
		assert.False(t, isNeo4j, "TuGraph should NOT be detected as Neo4j")
		assert.Equal(t, "TuGraph/3.0.0", serverStr)
	})

	t.Run("Memgraph SUCCESS - Bolt but NOT Neo4j", func(t *testing.T) {
		body := []byte{
			0xB1, SUCCESS_SIGNATURE,
			0xA1,
			0x86, 's', 'e', 'r', 'v', 'e', 'r',
			0x8E, // 14 chars
			'M', 'e', 'm', 'g', 'r', 'a', 'p', 'h', '/', '2', '.', '1', '0', '0',
		}
		raw := chunkMessage(body)

		serverStr, isNeo4j, err := parseHelloResponse(raw)
		require.NoError(t, err)
		assert.False(t, isNeo4j, "Memgraph should NOT be detected as Neo4j")
		assert.Equal(t, "Memgraph/2.100", serverStr)
	})

	t.Run("Neo4j FAILURE with Neo. error code", func(t *testing.T) {
		body := []byte{0xB1, FAILURE_SIGNATURE}
		body = append(body, []byte("Neo.ClientError.Security.Unauthorized")...)
		raw := chunkMessage(body)

		serverStr, isNeo4j, err := parseHelloResponse(raw)
		require.NoError(t, err)
		assert.True(t, isNeo4j, "Neo4j error code should confirm Neo4j")
		assert.Empty(t, serverStr, "version unknown from error")
	})

	t.Run("generic FAILURE without Neo. code - NOT Neo4j", func(t *testing.T) {
		body := []byte{0xB1, FAILURE_SIGNATURE}
		body = append(body, []byte("Authentication.Error.InvalidCredentials")...)
		raw := chunkMessage(body)

		_, isNeo4j, err := parseHelloResponse(raw)
		require.NoError(t, err)
		assert.False(t, isNeo4j, "generic error should not confirm Neo4j")
	})

	t.Run("multi-chunk message reassembly", func(t *testing.T) {
		body := []byte{
			0xB1, SUCCESS_SIGNATURE,
			0xA1,
			0x86, 's', 'e', 'r', 'v', 'e', 'r',
			0x8F,
			'N', 'e', 'o', '4', 'j', '/', '2', '0', '2', '5', '.', '1', '1', '.', '2',
		}
		// Split into two chunks
		chunk1 := body[:10]
		chunk2 := body[10:]
		raw := make([]byte, 0)
		raw = append(raw, 0x00, byte(len(chunk1)))
		raw = append(raw, chunk1...)
		raw = append(raw, 0x00, byte(len(chunk2)))
		raw = append(raw, chunk2...)
		raw = append(raw, 0x00, 0x00) // terminator

		serverStr, isNeo4j, err := parseHelloResponse(raw)
		require.NoError(t, err)
		assert.True(t, isNeo4j)
		assert.Equal(t, "Neo4j/2025.11.2", serverStr)
	})

	t.Run("malformed responses", func(t *testing.T) {
		malformed := []struct {
			raw  []byte
			desc string
		}{
			{[]byte{0x00, 0x01}, "truncated chunk"},
			{[]byte{0x00, 0x01, 0xB1, 0x00, 0x00}, "body too short"},
			{[]byte{0x00, 0x02, 0xA1, SUCCESS_SIGNATURE, 0x00, 0x00}, "wrong structure marker"},
		}

		for _, tc := range malformed {
			_, _, err := parseHelloResponse(tc.raw)
			assert.Error(t, err, "%s should error", tc.desc)
		}
	})
}

func TestContainsNeo4jErrorCode(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "Neo4j auth error",
			data: []byte("Neo.ClientError.Security.Unauthorized"),
			want: true,
		},
		{
			name: "Neo4j database error",
			data: []byte("Neo.DatabaseError.General.Unknown"),
			want: true,
		},
		{
			name: "Neo. prefix embedded in data",
			data: []byte("\x00\x00codeNeo.ClientError\x00"),
			want: true,
		},
		{
			name: "non-Neo4j error",
			data: []byte("Authentication.Error.Failed"),
			want: false,
		},
		{
			name: "partial Neo prefix",
			data: []byte("Neo"),
			want: false,
		},
		{
			name: "Neo without dot",
			data: []byte("NeoError"),
			want: false,
		},
		{
			name: "empty data",
			data: []byte{},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := containsNeo4jErrorCode(tc.data)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestExtractServerField(t *testing.T) {
	t.Run("tiny string value (<=15 chars)", func(t *testing.T) {
		// 0x8F = tiny string with 15 chars
		data := []byte{
			0xA1,
			0x86, 's', 'e', 'r', 'v', 'e', 'r',
			0x8F,
			'N', 'e', 'o', '4', 'j', '/', '2', '0', '2', '5', '.', '1', '1', '.', '2',
		}
		assert.Equal(t, "Neo4j/2025.11.2", extractServerField(data))
	})

	t.Run("String8 value (1-byte length)", func(t *testing.T) {
		// 0xD0 = String8 marker, followed by 1-byte length
		data := []byte{
			0xA1,
			0x86, 's', 'e', 'r', 'v', 'e', 'r',
			0xD0, 20, // String8 with 20 chars
			'N', 'e', 'o', '4', 'j', '/', '5', '.', '1', '3', '.', '0', ' ', 'C', 'o', 'm', 'm', 'u', 'n', 'y',
		}
		assert.Equal(t, "Neo4j/5.13.0 Communy", extractServerField(data))
	})

	t.Run("String16 value (2-byte length)", func(t *testing.T) {
		// 0xD1 = String16 marker, followed by 2-byte big-endian length
		value := "Neo4j/5.13.0 Community Edition"
		data := []byte{
			0xA1,
			0x86, 's', 'e', 'r', 'v', 'e', 'r',
			0xD1, 0x00, byte(len(value)),
		}
		data = append(data, []byte(value)...)
		assert.Equal(t, value, extractServerField(data))
	})

	t.Run("server field not present", func(t *testing.T) {
		data := []byte{
			0xA1,
			0x87, 'v', 'e', 'r', 's', 'i', 'o', 'n', // "version" key instead
			0x83, '5', '.', '0',
		}
		assert.Empty(t, extractServerField(data))
	})

	t.Run("server field with multiple map entries", func(t *testing.T) {
		data := []byte{
			0xA3, // Map with 3 entries
			0x8D, 'c', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n', '_', 'i', 'd',
			0x88, 'b', 'o', 'l', 't', '-', '1', '2', '3',
			0x86, 's', 'e', 'r', 'v', 'e', 'r',
			0x8C, 'N', 'e', 'o', '4', 'j', '/', '5', '.', '1', '3', '.', '0',
			0x8A, 'h', 'i', 'n', 't', 's', 0x00, 0x00, 0x00, 0x00,
		}
		assert.Equal(t, "Neo4j/5.13.0", extractServerField(data))
	})

	t.Run("empty data", func(t *testing.T) {
		assert.Empty(t, extractServerField([]byte{}))
	})

	t.Run("truncated value", func(t *testing.T) {
		data := []byte{
			0xA1,
			0x86, 's', 'e', 'r', 'v', 'e', 'r',
			0x8F, // Claims 15 chars but data ends
			'N', 'e', 'o',
		}
		assert.Empty(t, extractServerField(data))
	})
}

func TestDechunkBoltMessage(t *testing.T) {
	t.Run("single chunk", func(t *testing.T) {
		raw := []byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o', 0x00, 0x00}
		body, err := dechunkBoltMessage(raw)
		require.NoError(t, err)
		assert.Equal(t, []byte("hello"), body)
	})

	t.Run("multiple chunks", func(t *testing.T) {
		raw := []byte{
			0x00, 0x03, 'a', 'b', 'c',
			0x00, 0x02, 'd', 'e',
			0x00, 0x00,
		}
		body, err := dechunkBoltMessage(raw)
		require.NoError(t, err)
		assert.Equal(t, []byte("abcde"), body)
	})

	t.Run("error cases", func(t *testing.T) {
		errorCases := []struct {
			raw  []byte
			desc string
		}{
			{[]byte{0x00}, "too short"},
			{[]byte{0x00, 0x00}, "empty body"},
			{[]byte{0x00, 0x05, 'a', 'b', 'c'}, "truncated chunk"},
			{[]byte{0x00, 0x03, 'a', 'b', 'c'}, "missing terminator"},
		}

		for _, tc := range errorCases {
			_, err := dechunkBoltMessage(tc.raw)
			assert.Error(t, err, "%s should error", tc.desc)
		}
	})
}

func TestParseNeo4jVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Neo4j/5.13.0", "5.13.0"},
		{"Neo4j/2025.11.2", "2025.11.2"},
		{"Neo4j/4.4.28", "4.4.28"},
		{"Neo4j/5.13.0 Community", "5.13.0"},
		{"Neo4j/5.0.0 Enterprise Edition", "5.0.0"},
		{"TuGraph/3.0.0", ""},
		{"Memgraph/2.0", ""},
		{"", ""},
		{"5.13.0", ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.expected, parseNeo4jVersion(tc.input))
		})
	}
}

func TestBuildNeo4jCPE(t *testing.T) {
	tests := []struct {
		version  string
		expected string
	}{
		{"5.13.0", "cpe:2.3:a:neo4j:neo4j:5.13.0:*:*:*:*:*:*:*"},
		{"2025.11.2", "cpe:2.3:a:neo4j:neo4j:2025.11.2:*:*:*:*:*:*:*"},
		{"4.4.28", "cpe:2.3:a:neo4j:neo4j:4.4.28:*:*:*:*:*:*:*"},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			assert.Equal(t, tc.expected, buildNeo4jCPE(tc.version))
		})
	}
}

func chunkMessage(body []byte) []byte {
	msg := make([]byte, 2+len(body)+2)
	msg[0] = byte(len(body) >> 8)
	msg[1] = byte(len(body))
	copy(msg[2:], body)
	return msg
}
