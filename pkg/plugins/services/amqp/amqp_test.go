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

package amqp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestCheckAMQPProtocolHeader validates AMQP 0-9-1 protocol header structure
func TestCheckAMQPProtocolHeader(t *testing.T) {
	tests := []struct {
		name    string
		header  []byte
		wantErr bool
		errInfo string
	}{
		{
			name:    "Valid AMQP 0-9-1 header",
			header:  []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01},
			wantErr: false,
		},
		{
			name:    "Too short",
			header:  []byte{'A', 'M', 'Q', 'P'},
			wantErr: true,
			errInfo: "header too short",
		},
		{
			name:    "Invalid magic bytes",
			header:  []byte{'B', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01},
			wantErr: true,
			errInfo: "invalid AMQP magic bytes",
		},
		{
			name:    "AMQP 1.0 header (wrong version)",
			header:  []byte{'A', 'M', 'Q', 'P', 0x00, 0x01, 0x00, 0x00},
			wantErr: true,
			errInfo: "not AMQP 0-9-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkAMQPProtocolHeader(tt.header)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkAMQPProtocolHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParseConnectionStart validates parsing of AMQP Connection.Start frame
func TestParseConnectionStart(t *testing.T) {
	tests := []struct {
		name    string
		frame   []byte
		wantErr bool
		errInfo string
	}{
		{
			name: "Valid Connection.Start frame",
			frame: buildConnectionStartFrame(map[string]interface{}{
				"product": "RabbitMQ",
				"version": "3.13.0",
			}),
			wantErr: false,
		},
		{
			name:    "Too short",
			frame:   []byte{0x01, 0x00},
			wantErr: true,
			errInfo: "frame too short",
		},
		{
			name:    "Wrong frame type (not Method Frame)",
			frame:   buildInvalidFrameType(0x02),
			wantErr: true,
			errInfo: "not a method frame",
		},
		{
			name:    "Wrong channel (not 0)",
			frame:   buildInvalidChannel(1),
			wantErr: true,
			errInfo: "not on channel 0",
		},
		{
			name:    "Wrong method (not Connection.Start)",
			frame:   buildInvalidMethod(10, 11), // Connection.Start-Ok
			wantErr: true,
			errInfo: "not Connection.Start",
		},
		{
			name:    "Invalid frame end marker",
			frame:   buildInvalidFrameEnd(),
			wantErr: true,
			errInfo: "invalid frame end marker",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConnectionStart(tt.frame)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseConnectionStart() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestExtractServerProperties validates extraction of server properties from FieldTable
func TestExtractServerProperties(t *testing.T) {
	tests := []struct {
		name            string
		properties      map[string]interface{}
		wantProduct     string
		wantVersion     string
		wantPlatform    string
	}{
		{
			name: "RabbitMQ with all properties",
			properties: map[string]interface{}{
				"product":  "RabbitMQ",
				"version":  "3.13.0",
				"platform": "Erlang/OTP 26.2.1",
			},
			wantProduct:  "RabbitMQ",
			wantVersion:  "3.13.0",
			wantPlatform: "Erlang/OTP 26.2.1",
		},
		{
			name: "RabbitMQ without platform",
			properties: map[string]interface{}{
				"product": "RabbitMQ",
				"version": "3.12.0",
			},
			wantProduct:  "RabbitMQ",
			wantVersion:  "3.12.0",
			wantPlatform: "",
		},
		{
			name: "Apache Qpid",
			properties: map[string]interface{}{
				"product": "Qpid",
				"version": "0.32",
			},
			wantProduct:  "Qpid",
			wantVersion:  "0.32",
			wantPlatform: "",
		},
		{
			name:         "Empty properties",
			properties:   map[string]interface{}{},
			wantProduct:  "",
			wantVersion:  "",
			wantPlatform: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			product := extractStringField(tt.properties, "product")
			version := extractStringField(tt.properties, "version")
			platform := extractStringField(tt.properties, "platform")

			if product != tt.wantProduct {
				t.Errorf("extractStringField(product) = %v, want %v", product, tt.wantProduct)
			}
			if version != tt.wantVersion {
				t.Errorf("extractStringField(version) = %v, want %v", version, tt.wantVersion)
			}
			if platform != tt.wantPlatform {
				t.Errorf("extractStringField(platform) = %v, want %v", platform, tt.wantPlatform)
			}
		})
	}
}

// TestBuildAMQPCPE validates CPE generation for RabbitMQ
func TestBuildAMQPCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "RabbitMQ with version",
			version: "3.13.0",
			want:    "cpe:2.3:a:rabbitmq:rabbitmq:3.13.0:*:*:*:*:*:*:*",
		},
		{
			name:    "RabbitMQ 3.12",
			version: "3.12.0",
			want:    "cpe:2.3:a:rabbitmq:rabbitmq:3.12.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Unknown version (wildcard)",
			version: "",
			want:    "cpe:2.3:a:rabbitmq:rabbitmq:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildAMQPCPE(tt.version)
			if got != tt.want {
				t.Errorf("buildAMQPCPE() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAMQPPluginInterface validates the plugin implements the required interface methods
func TestAMQPPluginInterface(t *testing.T) {
	plugin := &AMQPPlugin{}

	t.Run("Name", func(t *testing.T) {
		if plugin.Name() != "amqp" {
			t.Errorf("Name() = %v, want %v", plugin.Name(), "amqp")
		}
	})

	t.Run("PortPriority", func(t *testing.T) {
		if !plugin.PortPriority(5672) {
			t.Errorf("PortPriority(5672) = false, want true")
		}
		if plugin.PortPriority(5671) {
			t.Errorf("PortPriority(5671) = true, want false (5671 is TLS variant)")
		}
		if plugin.PortPriority(80) {
			t.Errorf("PortPriority(80) = true, want false")
		}
	})

	t.Run("Priority", func(t *testing.T) {
		priority := plugin.Priority()
		if priority != 50 {
			t.Errorf("Priority() = %v, want 50 (binary protocol, run before HTTP)", priority)
		}
	})
}

// Helper functions to build test frames

// buildConnectionStartFrame constructs a valid AMQP Connection.Start method frame
func buildConnectionStartFrame(properties map[string]interface{}) []byte {
	buf := new(bytes.Buffer)

	// Frame Type: Method Frame (0x01)
	buf.WriteByte(0x01)

	// Channel: 0 (2 bytes, big-endian)
	binary.Write(buf, binary.BigEndian, uint16(0))

	// Payload (will calculate size later)
	payload := new(bytes.Buffer)

	// Class ID: 10 (Connection)
	binary.Write(payload, binary.BigEndian, uint16(10))

	// Method ID: 10 (Connection.Start)
	binary.Write(payload, binary.BigEndian, uint16(10))

	// version-major: 0
	payload.WriteByte(0)

	// version-minor: 9
	payload.WriteByte(9)

	// server-properties: FieldTable
	fieldTable := buildFieldTable(properties)
	binary.Write(payload, binary.BigEndian, uint32(len(fieldTable)))
	payload.Write(fieldTable)

	// mechanisms: longstr (e.g., "PLAIN AMQPLAIN")
	mechanisms := []byte("PLAIN AMQPLAIN")
	binary.Write(payload, binary.BigEndian, uint32(len(mechanisms)))
	payload.Write(mechanisms)

	// locales: longstr (e.g., "en_US")
	locales := []byte("en_US")
	binary.Write(payload, binary.BigEndian, uint32(len(locales)))
	payload.Write(locales)

	// Frame Size: payload length (4 bytes, big-endian)
	binary.Write(buf, binary.BigEndian, uint32(payload.Len()))

	// Payload
	buf.Write(payload.Bytes())

	// Frame End Marker: 0xCE
	buf.WriteByte(0xCE)

	return buf.Bytes()
}

// buildFieldTable constructs an AMQP FieldTable from a map
func buildFieldTable(fields map[string]interface{}) []byte {
	buf := new(bytes.Buffer)

	for key, value := range fields {
		// Field name: shortstr (length byte + string)
		buf.WriteByte(byte(len(key)))
		buf.WriteString(key)

		// Field value type: 'S' (longstr)
		buf.WriteByte('S')

		// Field value: longstr (4-byte length + string)
		strVal := value.(string)
		binary.Write(buf, binary.BigEndian, uint32(len(strVal)))
		buf.WriteString(strVal)
	}

	return buf.Bytes()
}

// buildInvalidFrameType creates a frame with wrong type
func buildInvalidFrameType(frameType byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(frameType) // Wrong frame type
	binary.Write(buf, binary.BigEndian, uint16(0))
	binary.Write(buf, binary.BigEndian, uint32(20))
	buf.Write(make([]byte, 20))
	buf.WriteByte(0xCE)
	return buf.Bytes()
}

// buildInvalidChannel creates a frame with wrong channel
func buildInvalidChannel(channel uint16) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(0x01) // Method frame
	binary.Write(buf, binary.BigEndian, channel) // Wrong channel
	binary.Write(buf, binary.BigEndian, uint32(20))
	buf.Write(make([]byte, 20))
	buf.WriteByte(0xCE)
	return buf.Bytes()
}

// buildInvalidMethod creates a frame with wrong class/method
func buildInvalidMethod(classID, methodID uint16) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(0x01)
	binary.Write(buf, binary.BigEndian, uint16(0))

	payload := new(bytes.Buffer)
	binary.Write(payload, binary.BigEndian, classID)
	binary.Write(payload, binary.BigEndian, methodID)

	binary.Write(buf, binary.BigEndian, uint32(payload.Len()))
	buf.Write(payload.Bytes())
	buf.WriteByte(0xCE)
	return buf.Bytes()
}

// buildInvalidFrameEnd creates a frame with wrong end marker
func buildInvalidFrameEnd() []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(0x01)
	binary.Write(buf, binary.BigEndian, uint16(0))
	binary.Write(buf, binary.BigEndian, uint32(20))
	buf.Write(make([]byte, 20))
	buf.WriteByte(0xFF) // Wrong end marker (should be 0xCE)
	return buf.Bytes()
}
