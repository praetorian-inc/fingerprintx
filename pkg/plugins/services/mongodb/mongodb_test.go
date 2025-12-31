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

package mongodb

import (
	"encoding/binary"
	"testing"
)

// TestParseBSONInt32 tests parsing of int32 values from BSON documents
func TestParseBSONInt32(t *testing.T) {
	tests := []struct {
		name     string
		bsonDoc  []byte
		key      string
		expected int32
		found    bool
	}{
		{
			name: "valid int32 value",
			bsonDoc: func() []byte {
				// Build BSON document: {maxWireVersion: 17}
				doc := make([]byte, 0, 64)
				// Document size (will be set at end)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)
				// Type: int32 (0x10)
				doc = append(doc, 0x10)
				// Key: "maxWireVersion" + null
				doc = append(doc, []byte("maxWireVersion")...)
				doc = append(doc, 0x00)
				// Value: 17 (int32, little-endian)
				valBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(valBuf, 17)
				doc = append(doc, valBuf...)
				// Document terminator
				doc = append(doc, 0x00)
				// Set document size
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "maxWireVersion",
			expected: 17,
			found:    true,
		},
		{
			name: "zero value",
			bsonDoc: func() []byte {
				doc := make([]byte, 0, 64)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)
				doc = append(doc, 0x10) // int32 type
				doc = append(doc, []byte("minWireVersion")...)
				doc = append(doc, 0x00)
				valBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(valBuf, 0)
				doc = append(doc, valBuf...)
				doc = append(doc, 0x00) // terminator
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "minWireVersion",
			expected: 0,
			found:    true,
		},
		{
			name: "key not found",
			bsonDoc: func() []byte {
				doc := make([]byte, 0, 64)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)
				doc = append(doc, 0x10) // int32 type
				doc = append(doc, []byte("otherKey")...)
				doc = append(doc, 0x00)
				valBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(valBuf, 42)
				doc = append(doc, valBuf...)
				doc = append(doc, 0x00) // terminator
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "maxWireVersion",
			expected: 0,
			found:    false,
		},
		{
			name:     "empty document",
			bsonDoc:  []byte{0x05, 0x00, 0x00, 0x00, 0x00}, // Minimal valid BSON doc
			key:      "maxWireVersion",
			expected: 0,
			found:    false,
		},
		{
			name:     "document too short",
			bsonDoc:  []byte{0x01, 0x02},
			key:      "maxWireVersion",
			expected: 0,
			found:    false,
		},
		{
			name: "wrong type (string instead of int32)",
			bsonDoc: func() []byte {
				doc := make([]byte, 0, 64)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)
				doc = append(doc, 0x02) // string type, not int32
				doc = append(doc, []byte("maxWireVersion")...)
				doc = append(doc, 0x00)
				// String value
				strLenBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(strLenBuf, 3) // "17" + null
				doc = append(doc, strLenBuf...)
				doc = append(doc, []byte("17")...)
				doc = append(doc, 0x00)
				doc = append(doc, 0x00) // terminator
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "maxWireVersion",
			expected: 0,
			found:    false,
		},
		{
			name: "multiple fields with target int32",
			bsonDoc: func() []byte {
				doc := make([]byte, 0, 128)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)

				// First field: string
				doc = append(doc, 0x02)
				doc = append(doc, []byte("msg")...)
				doc = append(doc, 0x00)
				strLenBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(strLenBuf, 9) // "isdbgrid" + null = 9 bytes
				doc = append(doc, strLenBuf...)
				doc = append(doc, []byte("isdbgrid")...)
				doc = append(doc, 0x00)

				// Second field: int32 (target)
				doc = append(doc, 0x10)
				doc = append(doc, []byte("maxWireVersion")...)
				doc = append(doc, 0x00)
				valBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(valBuf, 25)
				doc = append(doc, valBuf...)

				// Third field: another int32
				doc = append(doc, 0x10)
				doc = append(doc, []byte("minWireVersion")...)
				doc = append(doc, 0x00)
				minValBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(minValBuf, 6)
				doc = append(doc, minValBuf...)

				doc = append(doc, 0x00) // terminator
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "maxWireVersion",
			expected: 25,
			found:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, found := parseBSONInt32(tt.bsonDoc, tt.key)
			if found != tt.found {
				t.Errorf("parseBSONInt32() found = %v, want %v", found, tt.found)
			}
			if value != tt.expected {
				t.Errorf("parseBSONInt32() value = %v, want %v", value, tt.expected)
			}
		})
	}
}

// TestParseBSONString tests the existing parseBSONString function with edge cases
func TestParseBSONString(t *testing.T) {
	tests := []struct {
		name     string
		bsonDoc  []byte
		key      string
		expected string
	}{
		{
			name: "valid string value",
			bsonDoc: func() []byte {
				doc := make([]byte, 0, 64)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)
				doc = append(doc, 0x02) // string type
				doc = append(doc, []byte("msg")...)
				doc = append(doc, 0x00)
				strLenBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(strLenBuf, 9) // "isdbgrid" + null
				doc = append(doc, strLenBuf...)
				doc = append(doc, []byte("isdbgrid")...)
				doc = append(doc, 0x00)
				doc = append(doc, 0x00) // terminator
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "msg",
			expected: "isdbgrid",
		},
		{
			name: "version string",
			bsonDoc: func() []byte {
				doc := make([]byte, 0, 64)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)
				doc = append(doc, 0x02) // string type
				doc = append(doc, []byte("version")...)
				doc = append(doc, 0x00)
				strLenBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(strLenBuf, 6) // "8.0.4" + null
				doc = append(doc, strLenBuf...)
				doc = append(doc, []byte("8.0.4")...)
				doc = append(doc, 0x00)
				doc = append(doc, 0x00) // terminator
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "version",
			expected: "8.0.4",
		},
		{
			name:     "key not found",
			bsonDoc:  []byte{0x05, 0x00, 0x00, 0x00, 0x00},
			key:      "version",
			expected: "",
		},
		{
			name:     "empty document",
			bsonDoc:  []byte{},
			key:      "msg",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseBSONString(tt.bsonDoc, tt.key)
			if result != tt.expected {
				t.Errorf("parseBSONString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestCheckMongoDBResponse tests OP_REPLY validation
func TestCheckMongoDBResponse(t *testing.T) {
	tests := []struct {
		name              string
		response          []byte
		expectedRequestID uint32
		wantValid         bool
		wantErr           bool
	}{
		{
			name: "valid OP_REPLY response",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				// Message length
				lengthBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(lengthBuf, 60) // Will be adjusted
				resp = append(resp, lengthBuf...)
				// Request ID
				reqIDBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(reqIDBuf, 123)
				resp = append(resp, reqIDBuf...)
				// Response To
				respToBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(respToBuf, 100) // Expected request ID
				resp = append(resp, respToBuf...)
				// OpCode (OP_REPLY = 1)
				opcodeBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(opcodeBuf, OP_REPLY)
				resp = append(resp, opcodeBuf...)
				// Response flags (0)
				resp = append(resp, 0x00, 0x00, 0x00, 0x00)
				// CursorID
				resp = append(resp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
				// StartingFrom
				resp = append(resp, 0x00, 0x00, 0x00, 0x00)
				// NumberReturned
				resp = append(resp, 0x01, 0x00, 0x00, 0x00)
				// Minimal BSON document
				resp = append(resp, 0x05, 0x00, 0x00, 0x00, 0x00)
				// Update length
				binary.LittleEndian.PutUint32(resp[0:4], uint32(len(resp)))
				return resp
			}(),
			expectedRequestID: 100,
			wantValid:         true,
			wantErr:           false,
		},
		{
			name:              "response too short",
			response:          []byte{0x01, 0x02, 0x03},
			expectedRequestID: 100,
			wantValid:         false,
			wantErr:           true,
		},
		{
			name: "wrong opcode",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				lengthBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(lengthBuf, 60)
				resp = append(resp, lengthBuf...)
				reqIDBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(reqIDBuf, 123)
				resp = append(resp, reqIDBuf...)
				respToBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(respToBuf, 100)
				resp = append(resp, respToBuf...)
				// Wrong opcode (OP_MSG instead of OP_REPLY)
				opcodeBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(opcodeBuf, OP_MSG)
				resp = append(resp, opcodeBuf...)
				// Rest of data
				resp = append(resp, make([]byte, 20)...)
				resp = append(resp, 0x05, 0x00, 0x00, 0x00, 0x00) // BSON
				binary.LittleEndian.PutUint32(resp[0:4], uint32(len(resp)))
				return resp
			}(),
			expectedRequestID: 100,
			wantValid:         false,
			wantErr:           true,
		},
		{
			name: "mismatched request ID",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				lengthBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(lengthBuf, 60)
				resp = append(resp, lengthBuf...)
				reqIDBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(reqIDBuf, 123)
				resp = append(resp, reqIDBuf...)
				// Wrong responseTo value
				respToBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(respToBuf, 999) // Should be 100
				resp = append(resp, respToBuf...)
				opcodeBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(opcodeBuf, OP_REPLY)
				resp = append(resp, opcodeBuf...)
				resp = append(resp, make([]byte, 20)...)
				resp = append(resp, 0x05, 0x00, 0x00, 0x00, 0x00) // BSON
				binary.LittleEndian.PutUint32(resp[0:4], uint32(len(resp)))
				return resp
			}(),
			expectedRequestID: 100,
			wantValid:         false,
			wantErr:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := checkMongoDBResponse(tt.response, tt.expectedRequestID)
			if valid != tt.wantValid {
				t.Errorf("checkMongoDBResponse() valid = %v, want %v", valid, tt.wantValid)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("checkMongoDBResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCheckMongoDBMsgResponse tests OP_MSG validation
func TestCheckMongoDBMsgResponse(t *testing.T) {
	tests := []struct {
		name              string
		response          []byte
		expectedRequestID uint32
		wantValid         bool
		wantErr           bool
	}{
		{
			name: "valid OP_MSG response",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				// Message length
				lengthBuf := make([]byte, 4)
				resp = append(resp, lengthBuf...)
				// Request ID
				reqIDBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(reqIDBuf, 456)
				resp = append(resp, reqIDBuf...)
				// Response To
				respToBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(respToBuf, 200) // Expected request ID
				resp = append(resp, respToBuf...)
				// OpCode (OP_MSG = 2013)
				opcodeBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(opcodeBuf, OP_MSG)
				resp = append(resp, opcodeBuf...)
				// Flag bits
				resp = append(resp, 0x00, 0x00, 0x00, 0x00)
				// Section kind 0
				resp = append(resp, 0x00)
				// Minimal BSON document
				resp = append(resp, 0x05, 0x00, 0x00, 0x00, 0x00)
				// Update length
				binary.LittleEndian.PutUint32(resp[0:4], uint32(len(resp)))
				return resp
			}(),
			expectedRequestID: 200,
			wantValid:         true,
			wantErr:           false,
		},
		{
			name:              "response too short",
			response:          []byte{0x01, 0x02},
			expectedRequestID: 200,
			wantValid:         false,
			wantErr:           true,
		},
		{
			name: "wrong section kind",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				lengthBuf := make([]byte, 4)
				resp = append(resp, lengthBuf...)
				reqIDBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(reqIDBuf, 456)
				resp = append(resp, reqIDBuf...)
				respToBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(respToBuf, 200)
				resp = append(resp, respToBuf...)
				opcodeBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(opcodeBuf, OP_MSG)
				resp = append(resp, opcodeBuf...)
				resp = append(resp, 0x00, 0x00, 0x00, 0x00) // flags
				// Wrong section kind (1 instead of 0)
				resp = append(resp, 0x01)
				resp = append(resp, 0x05, 0x00, 0x00, 0x00, 0x00) // BSON
				binary.LittleEndian.PutUint32(resp[0:4], uint32(len(resp)))
				return resp
			}(),
			expectedRequestID: 200,
			wantValid:         false,
			wantErr:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := checkMongoDBMsgResponse(tt.response, tt.expectedRequestID)
			if valid != tt.wantValid {
				t.Errorf("checkMongoDBMsgResponse() valid = %v, want %v", valid, tt.wantValid)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("checkMongoDBMsgResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestBuildMongoDBQuery tests OP_QUERY message construction
func TestBuildMongoDBQuery(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		requestID uint32
	}{
		{
			name:      "hello command",
			command:   "hello",
			requestID: 1,
		},
		{
			name:      "isMaster command",
			command:   "isMaster",
			requestID: 2,
		},
		{
			name:      "buildInfo command",
			command:   "buildInfo",
			requestID: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := buildMongoDBQuery(tt.command, tt.requestID)

			// Verify message length field
			if len(query) < 16 {
				t.Fatal("Query too short")
			}

			messageLength := binary.LittleEndian.Uint32(query[0:4])
			if messageLength != uint32(len(query)) {
				t.Errorf("Message length mismatch: header says %d, actual %d", messageLength, len(query))
			}

			// Verify request ID
			requestID := binary.LittleEndian.Uint32(query[4:8])
			if requestID != tt.requestID {
				t.Errorf("Request ID mismatch: got %d, want %d", requestID, tt.requestID)
			}

			// Verify responseTo is 0
			responseTo := binary.LittleEndian.Uint32(query[8:12])
			if responseTo != 0 {
				t.Errorf("ResponseTo should be 0, got %d", responseTo)
			}

			// Verify opCode is OP_QUERY (2004)
			opCode := binary.LittleEndian.Uint32(query[12:16])
			if opCode != OP_QUERY {
				t.Errorf("OpCode should be OP_QUERY (2004), got %d", opCode)
			}
		})
	}
}

// TestBuildMongoDBMsgQuery tests OP_MSG message construction
func TestBuildMongoDBMsgQuery(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		requestID uint32
	}{
		{
			name:      "hello command",
			command:   "hello",
			requestID: 3,
		},
		{
			name:      "isMaster command",
			command:   "isMaster",
			requestID: 4,
		},
		{
			name:      "buildInfo command",
			command:   "buildInfo",
			requestID: 101,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := buildMongoDBMsgQuery(tt.command, tt.requestID)

			// Verify message length field
			if len(msg) < 16 {
				t.Fatal("Message too short")
			}

			messageLength := binary.LittleEndian.Uint32(msg[0:4])
			if messageLength != uint32(len(msg)) {
				t.Errorf("Message length mismatch: header says %d, actual %d", messageLength, len(msg))
			}

			// Verify request ID
			requestID := binary.LittleEndian.Uint32(msg[4:8])
			if requestID != tt.requestID {
				t.Errorf("Request ID mismatch: got %d, want %d", requestID, tt.requestID)
			}

			// Verify responseTo is 0
			responseTo := binary.LittleEndian.Uint32(msg[8:12])
			if responseTo != 0 {
				t.Errorf("ResponseTo should be 0, got %d", responseTo)
			}

			// Verify opCode is OP_MSG (2013)
			opCode := binary.LittleEndian.Uint32(msg[12:16])
			if opCode != OP_MSG {
				t.Errorf("OpCode should be OP_MSG (2013), got %d", opCode)
			}

			// Verify section kind is 0
			if len(msg) < 21 {
				t.Fatal("Message too short for section kind")
			}
			sectionKind := msg[20]
			if sectionKind != 0 {
				t.Errorf("Section kind should be 0, got %d", sectionKind)
			}
		})
	}
}
