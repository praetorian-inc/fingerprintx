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
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

/*
MongoDB Wire Protocol Fingerprinting

This plugin implements MongoDB fingerprinting using both legacy (OP_QUERY) and
modern (OP_MSG) wire protocols to ensure compatibility across all MongoDB versions
from ancient (pre-3.0) to unreleased future versions.

Detection Strategy:
  PHASE 1 - DETECTION (determines if the service is MongoDB):
    PRIMARY PATH (OP_QUERY): Works on ALL MongoDB versions
      - Try OP_QUERY + "hello" command (MongoDB 4.4+)
      - Fallback: OP_QUERY + "isMaster" command (all versions)
      - Note: MongoDB 5.1+ restricts OP_QUERY except for hello/isMaster handshake

    SECONDARY PATH (OP_MSG): Works on MongoDB 3.6+
      - Try OP_MSG + "hello" command (MongoDB 4.4+)
      - Fallback: OP_MSG + "isMaster" command (MongoDB 3.6+)

  PHASE 2 - ENRICHMENT (attempts to retrieve version information):
    After MongoDB is detected, attempt to retrieve version using "buildInfo" command:
      - Try OP_QUERY + "buildInfo" (works on all versions, requires no auth on most setups)
      - Fallback: OP_MSG + "buildInfo" (MongoDB 3.6+)
      - If buildInfo fails (e.g., requires authentication), detection still succeeds
      - Version field will be empty if retrieval fails

MongoDB Wire Protocol Message Structures:

OP_QUERY (Opcode 2004) - Legacy Protocol:
  Header (16 bytes):
    - messageLength (int32, little-endian)
    - requestID (int32, little-endian)
    - responseTo (int32, little-endian)
    - opCode (int32, little-endian) = 2004
  Body:
    - Flags (int32)
    - FullCollectionName (cstring) - e.g., "admin.$cmd"
    - NumberToSkip (int32)
    - NumberToReturn (int32)
    - Query document (BSON) - e.g., {"isMaster": 1}

OP_MSG (Opcode 2013) - Modern Protocol:
  Header (16 bytes):
    - messageLength (int32, little-endian)
    - requestID (int32, little-endian)
    - responseTo (int32, little-endian)
    - opCode (int32, little-endian) = 2013
  Body:
    - flagBits (uint32)
    - Section(s):
      - Section kind 0 (single document):
        - kind (1 byte) = 0
        - document (BSON) - e.g., {"hello": 1, "$db": "admin"}

OP_REPLY (Opcode 1) - Response to OP_QUERY:
  Header (16 bytes):
    - messageLength (int32, little-endian)
    - requestID (int32, little-endian)
    - responseTo (int32, little-endian)
    - opCode (int32, little-endian) = 1
  Body:
    - ResponseFlags (int32)
    - CursorID (int64)
    - StartingFrom (int32)
    - NumberReturned (int32)
    - Documents (BSON document(s))

OP_MSG Response - Response to OP_MSG:
  Header (16 bytes): Same as OP_MSG request
  Body:
    - flagBits (uint32)
    - Section(s): BSON document(s) with response data

Version Compatibility Matrix:
  - MongoDB 2.x - 3.4: OP_QUERY with isMaster only
  - MongoDB 3.6+: Both OP_QUERY and OP_MSG supported
  - MongoDB 4.4+: hello command introduced (preferred over isMaster)
  - MongoDB 5.1+: OP_QUERY restricted except for hello/isMaster handshake
  - Future versions: OP_MSG will continue to be supported
*/

type MONGODBPlugin struct{}

const MONGODB = "mongodb"

// mongoDBMetadata holds enriched metadata extracted from MongoDB responses
type mongoDBMetadata struct {
	Version        string // MongoDB version string (e.g., "8.0.4")
	MaxWireVersion int    // Maximum wire protocol version supported
	MinWireVersion int    // Minimum wire protocol version supported
	ServerType     string // "mongod" or "mongos"
}

// MongoDB wire protocol opcodes
const (
	OP_REPLY = 1
	OP_QUERY = 2004
	OP_MSG   = 2013
)

func init() {
	plugins.RegisterPlugin(&MONGODBPlugin{})
}

// checkMongoDBMsgResponse validates that the response is a valid MongoDB OP_MSG message.
//
// Parameters:
//   - response: The raw response bytes from the MongoDB server
//   - expectedRequestID: The request ID we expect to see in the responseTo field
//
// Returns:
//   - bool: true if the response is valid, false otherwise
//   - error: nil if valid, error details if validation fails
func checkMongoDBMsgResponse(response []byte, expectedRequestID uint32) (bool, error) {
	// Minimum size for OP_MSG response:
	// Header (16) + flagBits (4) + section kind (1) + minimal BSON (5) = 26 bytes
	if len(response) < 26 {
		return false, &utils.InvalidResponseErrorInfo{
			Service: MONGODB,
			Info:    "response is too short for a valid MongoDB OP_MSG message",
		}
	}

	// Check message length (first 4 bytes, little-endian)
	messageLength := binary.LittleEndian.Uint32(response[0:4])
	if messageLength < 26 || messageLength > 48*1024*1024 { // Max 48MB
		return false, &utils.InvalidResponseErrorInfo{
			Service: MONGODB,
			Info:    "invalid message length in MongoDB OP_MSG response",
		}
	}

	// Check if actual response length matches declared length
	if len(response) < int(messageLength) {
		return false, &utils.InvalidResponseErrorInfo{
			Service: MONGODB,
			Info:    "response length does not match declared message length",
		}
	}

	// Check responseTo matches our requestID (bytes 8-11, little-endian)
	responseTo := binary.LittleEndian.Uint32(response[8:12])
	if responseTo != expectedRequestID {
		return false, &utils.InvalidResponseErrorInfo{
			Service: MONGODB,
			Info:    fmt.Sprintf("responseTo (%d) does not match requestID (%d)", responseTo, expectedRequestID),
		}
	}

	// Check opCode (bytes 12-15, little-endian)
	opCode := binary.LittleEndian.Uint32(response[12:16])
	if opCode != OP_MSG {
		return false, &utils.InvalidResponseErrorInfo{
			Service: MONGODB,
			Info:    fmt.Sprintf("invalid opCode, expected OP_MSG (2013), got %d", opCode),
		}
	}

	// Check flagBits (bytes 16-19, little-endian)
	// We don't strictly validate flags, but we can check for obvious issues
	// For now, we just ensure they exist (already checked via length)

	// Validate section structure: kind byte should be 0 for single document
	sectionKind := response[20]
	if sectionKind != 0 {
		return false, &utils.InvalidResponseErrorInfo{
			Service: MONGODB,
			Info:    fmt.Sprintf("unexpected section kind, expected 0 (single document), got %d", sectionKind),
		}
	}

	return true, nil
}

// checkMongoDBResponse validates that the response is a valid MongoDB OP_REPLY message.
//
// Parameters:
//   - response: The raw response bytes from the MongoDB server
//   - expectedRequestID: The request ID we expect to see in the responseTo field
//
// Returns:
//   - bool: true if the response is valid, false otherwise
//   - error: nil if valid, error details if validation fails
func checkMongoDBResponse(response []byte, expectedRequestID uint32) (bool, error) {
	// Minimum size for OP_REPLY header is 16 bytes
	// After header: ResponseFlags (4) + CursorID (8) + StartingFrom (4) + NumberReturned (4) = 20 bytes
	// Total minimum: 36 bytes
	if len(response) < 36 {
		return false, &utils.InvalidResponseErrorInfo{
			Service: MONGODB,
			Info:    "response is too short for a valid MongoDB OP_REPLY message",
		}
	}

	// Check message length (first 4 bytes, little-endian)
	messageLength := binary.LittleEndian.Uint32(response[0:4])
	if messageLength < 36 || messageLength > 48*1024*1024 { // Max 48MB wire protocol message size
		return false, &utils.InvalidResponseErrorInfo{
			Service: MONGODB,
			Info:    "invalid message length in MongoDB response",
		}
	}

	// Check if actual response length matches declared length
	if len(response) < int(messageLength) {
		return false, &utils.InvalidResponseErrorInfo{
			Service: MONGODB,
			Info:    "response length does not match declared message length",
		}
	}

	// Check responseTo matches our requestID (bytes 8-11, little-endian)
	responseTo := binary.LittleEndian.Uint32(response[8:12])
	if responseTo != expectedRequestID {
		return false, &utils.InvalidResponseErrorInfo{
			Service: MONGODB,
			Info:    fmt.Sprintf("responseTo (%d) does not match requestID (%d)", responseTo, expectedRequestID),
		}
	}

	// Check opCode (bytes 12-15, little-endian)
	opCode := binary.LittleEndian.Uint32(response[12:16])
	if opCode != OP_REPLY {
		return false, &utils.InvalidResponseErrorInfo{
			Service: MONGODB,
			Info:    fmt.Sprintf("invalid opCode, expected OP_REPLY (1), got %d", opCode),
		}
	}

	// Check response flags (bytes 16-19, little-endian)
	responseFlags := binary.LittleEndian.Uint32(response[16:20])
	// Bit 0: CursorNotFound
	// Bit 1: QueryFailure
	if responseFlags&0x02 != 0 { // QueryFailure bit
		return false, &utils.InvalidResponseErrorInfo{
			Service: MONGODB,
			Info:    "MongoDB query failed (QueryFailure flag set)",
		}
	}

	return true, nil
}

// parseBSONString extracts a string value for a given key from a BSON document
// This is a minimal BSON parser focused on extracting string values
func parseBSONString(bsonDoc []byte, key string) string {
	if len(bsonDoc) < 5 {
		return ""
	}

	// BSON document format:
	// int32 - document size
	// elements...
	// 0x00 - terminator

	docSize := binary.LittleEndian.Uint32(bsonDoc[0:4])
	if docSize > uint32(len(bsonDoc)) {
		return ""
	}

	pos := 4 // Start after size field
	for pos < len(bsonDoc)-1 {
		// Check for document terminator
		if bsonDoc[pos] == 0x00 {
			break
		}

		// Read element type
		elementType := bsonDoc[pos]
		pos++

		// Read key (null-terminated string)
		keyStart := pos
		for pos < len(bsonDoc) && bsonDoc[pos] != 0x00 {
			pos++
		}
		if pos >= len(bsonDoc) {
			return ""
		}
		elementKey := string(bsonDoc[keyStart:pos])
		pos++ // Skip null terminator

		// If this is our target key and it's a string type (0x02)
		if elementKey == key && elementType == 0x02 {
			// String format: int32 length (including null terminator) + string + null
			if pos+4 > len(bsonDoc) {
				return ""
			}
			strLen := binary.LittleEndian.Uint32(bsonDoc[pos : pos+4])
			pos += 4
			if pos+int(strLen) > len(bsonDoc) || strLen == 0 {
				return ""
			}
			// Return string without null terminator
			return string(bsonDoc[pos : pos+int(strLen)-1])
		}

		// Skip value based on type
		switch elementType {
		case 0x01: // double
			pos += 8
		case 0x02: // string
			if pos+4 > len(bsonDoc) {
				return ""
			}
			strLen := binary.LittleEndian.Uint32(bsonDoc[pos : pos+4])
			pos += 4 + int(strLen)
		case 0x03, 0x04: // document, array
			if pos+4 > len(bsonDoc) {
				return ""
			}
			subDocLen := binary.LittleEndian.Uint32(bsonDoc[pos : pos+4])
			pos += int(subDocLen)
		case 0x05: // binary
			if pos+5 > len(bsonDoc) {
				return ""
			}
			binLen := binary.LittleEndian.Uint32(bsonDoc[pos : pos+4])
			pos += 5 + int(binLen)
		case 0x07: // ObjectId
			pos += 12
		case 0x08: // boolean
			pos++
		case 0x09: // UTC datetime
			pos += 8
		case 0x0A: // null
			// no value
		case 0x10: // int32
			pos += 4
		case 0x11, 0x12: // timestamp, int64
			pos += 8
		default:
			// Unknown type, cannot continue parsing safely
			return ""
		}
	}

	return ""
}

// parseBSONInt32 extracts an int32 value for a given key from a BSON document.
// This is a minimal BSON parser focused on extracting int32 values for wire version fields.
//
// Parameters:
//   - bsonDoc: The BSON document bytes to parse
//   - key: The key name to search for
//
// Returns:
//   - int32: The extracted value (0 if not found)
//   - bool: true if the key was found and successfully extracted, false otherwise
func parseBSONInt32(bsonDoc []byte, key string) (int32, bool) {
	if len(bsonDoc) < 5 {
		return 0, false
	}

	// BSON document format:
	// int32 - document size
	// elements...
	// 0x00 - terminator

	docSize := binary.LittleEndian.Uint32(bsonDoc[0:4])
	if docSize > uint32(len(bsonDoc)) {
		return 0, false
	}

	pos := 4 // Start after size field
	for pos < len(bsonDoc)-1 {
		// Check for document terminator
		if bsonDoc[pos] == 0x00 {
			break
		}

		// Read element type
		elementType := bsonDoc[pos]
		pos++

		// Read key (null-terminated string)
		keyStart := pos
		for pos < len(bsonDoc) && bsonDoc[pos] != 0x00 {
			pos++
		}
		if pos >= len(bsonDoc) {
			return 0, false
		}
		elementKey := string(bsonDoc[keyStart:pos])
		pos++ // Skip null terminator

		// If this is our target key and it's an int32 type (0x10)
		if elementKey == key && elementType == 0x10 {
			// int32 format: 4 bytes, little-endian
			if pos+4 > len(bsonDoc) {
				return 0, false
			}
			value := int32(binary.LittleEndian.Uint32(bsonDoc[pos : pos+4]))
			return value, true
		}

		// Skip value based on type
		switch elementType {
		case 0x01: // double
			pos += 8
		case 0x02: // string
			if pos+4 > len(bsonDoc) {
				return 0, false
			}
			strLen := binary.LittleEndian.Uint32(bsonDoc[pos : pos+4])
			pos += 4 + int(strLen)
		case 0x03, 0x04: // document, array
			if pos+4 > len(bsonDoc) {
				return 0, false
			}
			subDocLen := binary.LittleEndian.Uint32(bsonDoc[pos : pos+4])
			pos += int(subDocLen)
		case 0x05: // binary
			if pos+5 > len(bsonDoc) {
				return 0, false
			}
			binLen := binary.LittleEndian.Uint32(bsonDoc[pos : pos+4])
			pos += 5 + int(binLen)
		case 0x07: // ObjectId
			pos += 12
		case 0x08: // boolean
			pos++
		case 0x09: // UTC datetime
			pos += 8
		case 0x0A: // null
			// no value
		case 0x10: // int32
			pos += 4
		case 0x11, 0x12: // timestamp, int64
			pos += 8
		default:
			// Unknown type, cannot continue parsing safely
			return 0, false
		}
	}

	return 0, false
}

// parseMaxWireVersion extracts maxWireVersion from a BSON document.
// Wire versions map to MongoDB versions and indicate protocol capabilities.
//
// Parameters:
//   - bsonDoc: The BSON document bytes to parse
//
// Returns:
//   - int: maxWireVersion if found, 0 otherwise
//   - bool: true if found, false otherwise
func parseMaxWireVersion(bsonDoc []byte) (int, bool) {
	value, found := parseBSONInt32(bsonDoc, "maxWireVersion")
	return int(value), found
}

// parseMinWireVersion extracts minWireVersion from a BSON document.
// Indicates the minimum wire protocol version supported by the server.
//
// Parameters:
//   - bsonDoc: The BSON document bytes to parse
//
// Returns:
//   - int: minWireVersion if found, 0 otherwise
//   - bool: true if found, false otherwise
func parseMinWireVersion(bsonDoc []byte) (int, bool) {
	value, found := parseBSONInt32(bsonDoc, "minWireVersion")
	return int(value), found
}

// parseServerType extracts server type from a BSON document.
// If msg field contains "isdbgrid", this is a mongos (query router).
// Otherwise, it's a mongod (database server).
//
// Parameters:
//   - bsonDoc: The BSON document bytes to parse
//
// Returns:
//   - string: "mongos" if msg=="isdbgrid", "mongod" otherwise
func parseServerType(bsonDoc []byte) string {
	msg := parseBSONString(bsonDoc, "msg")
	if msg == "isdbgrid" {
		return "mongos"
	}
	return "mongod"
}

// parseMongoDBMsgMetadata extracts complete metadata from an OP_MSG response.
//
// Parameters:
//   - response: The raw OP_MSG response bytes from the MongoDB server
//
// Returns:
//   - mongoDBMetadata: Extracted metadata (version, wire versions, server type)
func parseMongoDBMsgMetadata(response []byte) mongoDBMetadata {
	metadata := mongoDBMetadata{
		ServerType: "mongod", // Default to mongod
	}

	// OP_MSG structure:
	// Header (16 bytes) + flagBits (4 bytes) + section kind (1 byte) + BSON document
	// BSON documents start at offset 21

	if len(response) < 21 {
		return metadata
	}

	// BSON documents start at offset 21
	bsonDoc := response[21:]

	// Extract version (try "version" first, then "versionString")
	version := parseBSONString(bsonDoc, "version")
	if version == "" {
		version = parseBSONString(bsonDoc, "versionString")
	}
	metadata.Version = version

	// Extract wire versions
	if maxWire, found := parseMaxWireVersion(bsonDoc); found {
		metadata.MaxWireVersion = maxWire
	}
	if minWire, found := parseMinWireVersion(bsonDoc); found {
		metadata.MinWireVersion = minWire
	}

	// Extract server type (mongos vs mongod)
	metadata.ServerType = parseServerType(bsonDoc)

	return metadata
}

// parseMongoDBMsgVersion attempts to extract version information from an OP_MSG response.
// Deprecated: Use parseMongoDBMsgMetadata for enriched metadata extraction.
//
// Parameters:
//   - response: The raw OP_MSG response bytes from the MongoDB server
//
// Returns:
//   - string: The version string if found, empty string otherwise
func parseMongoDBMsgVersion(response []byte) string {
	metadata := parseMongoDBMsgMetadata(response)
	return metadata.Version
}

// parseMongoDBMetadata extracts complete metadata from an OP_REPLY response.
//
// Parameters:
//   - response: The raw OP_REPLY response bytes from the MongoDB server
//
// Returns:
//   - mongoDBMetadata: Extracted metadata (version, wire versions, server type)
func parseMongoDBMetadata(response []byte) mongoDBMetadata {
	metadata := mongoDBMetadata{
		ServerType: "mongod", // Default to mongod
	}

	// OP_REPLY structure:
	// Header (16 bytes) + ResponseFlags (4) + CursorID (8) + StartingFrom (4) + NumberReturned (4) = 36 bytes
	// Then BSON documents start at offset 36

	if len(response) < 36 {
		return metadata
	}

	// BSON documents start at offset 36
	bsonDoc := response[36:]

	// Extract version (try "version" first, then "versionString")
	version := parseBSONString(bsonDoc, "version")
	if version == "" {
		version = parseBSONString(bsonDoc, "versionString")
	}
	metadata.Version = version

	// Extract wire versions
	if maxWire, found := parseMaxWireVersion(bsonDoc); found {
		metadata.MaxWireVersion = maxWire
	}
	if minWire, found := parseMinWireVersion(bsonDoc); found {
		metadata.MinWireVersion = minWire
	}

	// Extract server type (mongos vs mongod)
	metadata.ServerType = parseServerType(bsonDoc)

	return metadata
}

// parseMongoDBVersion attempts to extract version information from an OP_REPLY response.
// Deprecated: Use parseMongoDBMetadata for enriched metadata extraction.
//
// Parameters:
//   - response: The raw OP_REPLY response bytes from the MongoDB server
//
// Returns:
//   - string: The version string if found, empty string otherwise
func parseMongoDBVersion(response []byte) string {
	metadata := parseMongoDBMetadata(response)
	return metadata.Version
}

// buildMongoDBMsgQuery constructs an OP_MSG wire protocol message for the
// specified command. The command is sent to the "admin" database as required
// by the MongoDB wire protocol specification.
//
// Parameters:
//   - command: MongoDB command name (e.g., "hello", "isMaster", "buildInfo")
//   - requestID: Unique identifier for this request
//
// Returns:
//   - []byte: Properly formatted OP_MSG message ready to send
func buildMongoDBMsgQuery(command string, requestID uint32) []byte {
	// Build BSON document: {command: 1, "$db": "admin"}
	// OP_MSG requires "$db" field (unlike OP_QUERY which uses collection name)

	commandBytes := []byte(command)
	dbBytes := []byte("$db")
	adminBytes := []byte("admin")

	// Calculate BSON document size:
	// 4 (size field) + 1 (type) + len(command) + 1 (null) + 8 (double value) +
	// 1 (type) + len("$db") + 1 (null) + 4 (string length) + len("admin") + 1 (null) + 1 (terminator)
	bsonSize := uint32(4 + 1 + len(commandBytes) + 1 + 8 + 1 + len(dbBytes) + 1 + 4 + len(adminBytes) + 1 + 1)

	bsonDoc := make([]byte, 0, bsonSize)

	// Document size (includes the size field itself)
	sizeBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuf, bsonSize)
	bsonDoc = append(bsonDoc, sizeBuf...)

	// First element: command with value 1.0 (double type 0x01)
	bsonDoc = append(bsonDoc, 0x01) // Type: double
	bsonDoc = append(bsonDoc, commandBytes...)
	bsonDoc = append(bsonDoc, 0x00) // Null terminator
	// Value: 1.0 as double (little-endian)
	bsonDoc = append(bsonDoc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F)

	// Second element: "$db" with value "admin" (string type 0x02)
	bsonDoc = append(bsonDoc, 0x02) // Type: string
	bsonDoc = append(bsonDoc, dbBytes...)
	bsonDoc = append(bsonDoc, 0x00) // Null terminator
	// String length (including null terminator)
	strLenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(strLenBuf, uint32(len(adminBytes)+1))
	bsonDoc = append(bsonDoc, strLenBuf...)
	bsonDoc = append(bsonDoc, adminBytes...)
	bsonDoc = append(bsonDoc, 0x00) // String null terminator

	// Document terminator
	bsonDoc = append(bsonDoc, 0x00)

	// Build OP_MSG message
	msg := []byte{
		// Message length (will be set after construction) - 4 bytes
		0x00, 0x00, 0x00, 0x00,
	}

	// Request ID (little-endian) - 4 bytes
	reqIDBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(reqIDBuf, requestID)
	msg = append(msg, reqIDBuf...)

	// ResponseTo (0) - 4 bytes
	msg = append(msg, 0x00, 0x00, 0x00, 0x00)

	// OpCode OP_MSG (2013, little-endian) - 4 bytes
	msg = append(msg, 0xDD, 0x07, 0x00, 0x00)

	// FlagBits (0) - 4 bytes
	msg = append(msg, 0x00, 0x00, 0x00, 0x00)

	// Section kind 0 (single BSON document) - 1 byte
	msg = append(msg, 0x00)

	// Append BSON document
	msg = append(msg, bsonDoc...)

	// Set message length (includes the length field itself)
	messageLength := uint32(len(msg))
	binary.LittleEndian.PutUint32(msg[0:4], messageLength)

	return msg
}

// buildMongoDBQuery constructs an OP_QUERY wire protocol message for the
// specified command. The command is sent to the "admin.$cmd" collection as required
// by the legacy MongoDB wire protocol specification.
//
// Parameters:
//   - command: MongoDB command name (e.g., "hello", "isMaster", "buildInfo")
//   - requestID: Unique identifier for this request
//
// Returns:
//   - []byte: Properly formatted OP_QUERY message ready to send
func buildMongoDBQuery(command string, requestID uint32) []byte {
	// Build the query message
	// Header: messageLength (will be calculated), requestID, responseTo (0), opCode (2004)
	// Flags: 0
	// FullCollectionName: "admin.$cmd\0"
	// NumberToSkip: 0
	// NumberToReturn: -1 (0xFFFFFFFF)
	// Document: {command: 1}

	// Build BSON document: {command: 1}
	// BSON format: int32 size + elements + 0x00 terminator
	// Element format: type(1 byte) + key(null-terminated) + value

	commandBytes := []byte(command)
	// BSON document size = 4 (size field) + 1 (type) + len(command) + 1 (null) + 8 (double value) + 1 (terminator)
	bsonSize := uint32(4 + 1 + len(commandBytes) + 1 + 8 + 1)

	bsonDoc := make([]byte, 0, bsonSize)
	// Document size (includes the size field itself)
	sizeBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuf, bsonSize)
	bsonDoc = append(bsonDoc, sizeBuf...)
	// Type: double (0x01)
	bsonDoc = append(bsonDoc, 0x01)
	// Key: command name + null terminator
	bsonDoc = append(bsonDoc, commandBytes...)
	bsonDoc = append(bsonDoc, 0x00)
	// Value: 1.0 as double (little-endian)
	bsonDoc = append(bsonDoc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F)
	// Document terminator
	bsonDoc = append(bsonDoc, 0x00)

	// Build full OP_QUERY message
	query := []byte{
		// Message length (will be set after construction) - 4 bytes
		0x00, 0x00, 0x00, 0x00,
	}

	// Request ID (little-endian) - 4 bytes
	reqIDBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(reqIDBuf, requestID)
	query = append(query, reqIDBuf...)

	// ResponseTo (0) - 4 bytes
	query = append(query, 0x00, 0x00, 0x00, 0x00)

	// OpCode OP_QUERY (2004, little-endian) - 4 bytes
	query = append(query, 0xd4, 0x07, 0x00, 0x00)

	// Flags (0) - 4 bytes
	query = append(query, 0x00, 0x00, 0x00, 0x00)

	// FullCollectionName: "admin.$cmd\0"
	query = append(query, []byte("admin.$cmd")...)
	query = append(query, 0x00)

	// NumberToSkip (0) - 4 bytes
	query = append(query, 0x00, 0x00, 0x00, 0x00)

	// NumberToReturn (-1, 0xFFFFFFFF) - 4 bytes
	query = append(query, 0xFF, 0xFF, 0xFF, 0xFF)

	// Append BSON document
	query = append(query, bsonDoc...)

	// Set message length (includes the length field itself)
	messageLength := uint32(len(query))
	binary.LittleEndian.PutUint32(query[0:4], messageLength)

	return query
}

// tryGetMongoDBVersion attempts to retrieve the MongoDB version using the buildInfo command.
// This function is called AFTER MongoDB has been detected to enrich the result with version info.
// If buildInfo fails (e.g., requires auth), we gracefully return empty string without error.
//
// Parameters:
//   - conn: Network connection to the MongoDB server
//   - timeout: Timeout duration for network operations
//
// Returns:
//   - string: Version string if retrieved, empty string otherwise
func tryGetMongoDBVersion(conn net.Conn, timeout time.Duration) string {
	// Try OP_QUERY buildInfo first (works on all versions)
	requestID := uint32(100)
	buildInfoQuery := buildMongoDBQuery("buildInfo", requestID)

	response, err := utils.SendRecv(conn, buildInfoQuery, timeout)
	if err == nil && len(response) > 0 {
		isValid, err := checkMongoDBResponse(response, requestID)
		if isValid && err == nil {
			version := parseMongoDBVersion(response)
			if version != "" {
				return version
			}
		}
	}

	// Try OP_MSG buildInfo (MongoDB 3.6+)
	requestID = uint32(101)
	buildInfoMsg := buildMongoDBMsgQuery("buildInfo", requestID)

	response, err = utils.SendRecv(conn, buildInfoMsg, timeout)
	if err == nil && len(response) > 0 {
		isValid, err := checkMongoDBMsgResponse(response, requestID)
		if isValid && err == nil {
			version := parseMongoDBMsgVersion(response)
			if version != "" {
				return version
			}
		}
	}

	// Could not retrieve version (possibly requires auth), return empty
	return ""
}

// tryMongoDBMsgProtocol attempts MongoDB detection using the OP_MSG wire protocol.
// This protocol only works on MongoDB 3.6+ (maxWireVersion >= 6).
//
// Parameters:
//   - conn: Network connection to the MongoDB server
//   - timeout: Timeout duration for network operations
//
// Returns:
//   - mongoDBMetadata: Enriched metadata (version, wire versions, server type)
//   - bool: true if this appears to be MongoDB (even if metadata extraction fails)
//   - error: Error details if detection failed
func tryMongoDBMsgProtocol(conn net.Conn, timeout time.Duration) (mongoDBMetadata, bool, error) {
	// Try "hello" command first (modern MongoDB 4.4+)
	requestID := uint32(3)
	helloMsg := buildMongoDBMsgQuery("hello", requestID)

	response, err := utils.SendRecv(conn, helloMsg, timeout)
	if err != nil {
		return mongoDBMetadata{}, false, err
	}
	if len(response) == 0 {
		return mongoDBMetadata{}, true, &utils.ServerNotEnable{}
	}

	isMongoDB, err := checkMongoDBMsgResponse(response, requestID)
	if isMongoDB && err == nil {
		metadata := parseMongoDBMsgMetadata(response)
		return metadata, true, nil
	}

	// Try legacy isMaster command as fallback
	requestID = uint32(4)
	isMasterMsg := buildMongoDBMsgQuery("isMaster", requestID)

	response, err = utils.SendRecv(conn, isMasterMsg, timeout)
	if err != nil {
		return mongoDBMetadata{}, false, err
	}
	if len(response) == 0 {
		return mongoDBMetadata{}, true, &utils.ServerNotEnable{}
	}

	isMongoDB, err = checkMongoDBMsgResponse(response, requestID)
	if !isMongoDB {
		return mongoDBMetadata{}, true, &utils.InvalidResponseError{Service: MONGODB}
	}

	metadata := parseMongoDBMsgMetadata(response)
	return metadata, true, nil
}

// tryMongoDBQueryProtocol attempts MongoDB detection using the OP_QUERY wire protocol.
// This protocol works on ALL MongoDB versions, including 5.1+ where OP_QUERY is otherwise
// restricted (hello/isMaster handshake commands are still supported).
//
// Parameters:
//   - conn: Network connection to the MongoDB server
//   - timeout: Timeout duration for network operations
//
// Returns:
//   - mongoDBMetadata: Enriched metadata (version, wire versions, server type)
//   - bool: true if this appears to be MongoDB (even if metadata extraction fails)
//   - error: Error details if detection failed
func tryMongoDBQueryProtocol(conn net.Conn, timeout time.Duration) (mongoDBMetadata, bool, error) {
	// Try "hello" command first (modern MongoDB 4.4+)
	requestID := uint32(1)
	helloQuery := buildMongoDBQuery("hello", requestID)

	response, err := utils.SendRecv(conn, helloQuery, timeout)
	if err != nil {
		return mongoDBMetadata{}, false, err
	}
	if len(response) == 0 {
		return mongoDBMetadata{}, true, &utils.ServerNotEnable{}
	}

	isMongoDB, err := checkMongoDBResponse(response, requestID)
	if isMongoDB && err == nil {
		metadata := parseMongoDBMetadata(response)
		return metadata, true, nil
	}

	// Try legacy isMaster command as fallback
	requestID = uint32(2)
	isMasterQuery := buildMongoDBQuery("isMaster", requestID)

	response, err = utils.SendRecv(conn, isMasterQuery, timeout)
	if err != nil {
		return mongoDBMetadata{}, false, err
	}
	if len(response) == 0 {
		return mongoDBMetadata{}, true, &utils.ServerNotEnable{}
	}

	isMongoDB, err = checkMongoDBResponse(response, requestID)
	if !isMongoDB {
		return mongoDBMetadata{}, true, &utils.InvalidResponseError{Service: MONGODB}
	}

	metadata := parseMongoDBMetadata(response)
	return metadata, true, nil
}

// DetectMongoDB performs MongoDB fingerprinting using a layered fallback approach.
// It attempts detection using both OP_QUERY (universal) and OP_MSG (MongoDB 3.6+) protocols
// to ensure compatibility across all MongoDB versions from ancient to unreleased.
//
// Detection Strategy:
//  1. DETECTION PHASE: Use hello/isMaster commands to detect MongoDB and extract metadata
//     - PRIMARY PATH (OP_QUERY): Try OP_QUERY + "hello", then OP_QUERY + "isMaster"
//       Works on ALL MongoDB versions, including 5.1+ (handshake exception)
//       Extracts: version, maxWireVersion, minWireVersion, serverType
//     - SECONDARY PATH (OP_MSG): Try OP_MSG + "hello", then OP_MSG + "isMaster"
//       Works on MongoDB 3.6+ only
//       Extracts: version, maxWireVersion, minWireVersion, serverType
//  2. ENRICHMENT PHASE: If version not found in hello/isMaster, try buildInfo
//     - Attempts buildInfo with both OP_QUERY and OP_MSG protocols
//     - If buildInfo fails (e.g., requires auth), still returns MongoDB detection
//
// Parameters:
//   - conn: Network connection to the MongoDB server
//   - timeout: Timeout duration for network operations
//
// Returns:
//   - mongoDBMetadata: Enriched metadata (version, wire versions, server type)
//   - bool: true if this appears to be MongoDB
//   - error: Error details if detection failed
func DetectMongoDB(conn net.Conn, timeout time.Duration) (mongoDBMetadata, bool, error) {
	// PHASE 1: Detect MongoDB using hello/isMaster commands
	// Try OP_QUERY first (works on all versions)
	metadata, isDetected, err := tryMongoDBQueryProtocol(conn, timeout)
	if isDetected && err == nil {
		// MongoDB detected! If version not found in hello/isMaster, try buildInfo
		if metadata.Version == "" {
			metadata.Version = tryGetMongoDBVersion(conn, timeout)
		}
		return metadata, true, nil
	}

	// Fallback to OP_MSG (MongoDB 3.6+)
	metadata, isDetected, err = tryMongoDBMsgProtocol(conn, timeout)
	if isDetected && err == nil {
		// MongoDB detected! If version not found in hello/isMaster, try buildInfo
		if metadata.Version == "" {
			metadata.Version = tryGetMongoDBVersion(conn, timeout)
		}
		return metadata, true, nil
	}

	// Both detection methods failed
	return mongoDBMetadata{}, false, &utils.InvalidResponseError{Service: MONGODB}
}

// buildMongoDBCPE constructs a CPE (Common Platform Enumeration) string for MongoDB.
// CPE format: cpe:2.3:a:mongodb:mongodb:{version}:*:*:*:*:*:*:*
//
// Parameters:
//   - version: MongoDB version string (e.g., "8.0.4")
//
// Returns:
//   - string: CPE string, or empty if version is empty
func buildMongoDBCPE(version string) string {
	if version == "" {
		return ""
	}
	// Sanitize version string to only include version number (remove any extra metadata)
	// MongoDB versions are typically in format "X.Y.Z" or "X.Y.Z-rcN"
	version = strings.Split(version, " ")[0] // Remove any trailing metadata
	return fmt.Sprintf("cpe:2.3:a:mongodb:mongodb:%s:*:*:*:*:*:*:*", version)
}

func (p *MONGODBPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	metadata, check, err := DetectMongoDB(conn, timeout)
	if check && err != nil {
		return nil, nil
	} else if check && err == nil {
		payload := plugins.ServiceMongoDB{
			MaxWireVersion: metadata.MaxWireVersion,
			MinWireVersion: metadata.MinWireVersion,
			ServerType:     metadata.ServerType,
		}
		if metadata.Version != "" {
			cpe := buildMongoDBCPE(metadata.Version)
			if cpe != "" {
				payload.CPEs = []string{cpe}
			}
		}
		return plugins.CreateServiceFrom(target, payload, false, metadata.Version, plugins.TCP), nil
	}
	return nil, err
}

func (p *MONGODBPlugin) PortPriority(port uint16) bool {
	return port == 27017
}

func (p *MONGODBPlugin) Name() string {
	return MONGODB
}

func (p *MONGODBPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *MONGODBPlugin) Priority() int {
	return -1
}

