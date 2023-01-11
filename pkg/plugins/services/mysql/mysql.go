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

package mysql

import (
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

/*
When we perform fingerprinting of the MySQL service, we can expect to get one
of two packets back from the server on the initial connection. The first would
be an initial handshake packet indicating we can authenticate to the server.

The second potential response would be an error message returned by the server
telling us why we can't authenticate. For example, the server may respond with
an error message stating the client IP is not allowed to authenticate to the
server.

 Example MySQL Initial Handshake Packet:
   Length: 4a 00 00 00
   Version: 0a
   Server Version: 38 2e 30  2e 32 38 00 (null terminated string "8.0.28")
   Connection Id: 0b 00 00 00
   Auth-Plugin-Data-Part-1: 15 05 6c 51 28 32 48 15
   Filler: 00
   Capability Flags: ff ff
   Character Set: ff
   Status Flags: 02 00
   Capability Flags: ff df
   Length of Auth Plugin Data: 15
   Reserved (all 00): 00 00 00 00 00 00 00 00 00 00
   Auth-Plugin-Data-Part-2 (len 13 base 10): 26 68 15 1e 2e 7f 69 38 52 6b 6c 5c 00
   Auth Plugin Name: null terminated string "caching_sha2_password"

 Example MySQL Error Packet on Initial Connection:
   Packet Length: 45 00 00 00
   Header: ff
   Error Code: 6a 04
   Human Readable Error Message: Host '50.82.91.234' is not allowed to connect to this MySQL server
*/

type MYSQLPlugin struct{}

const (
	// protocolVersion = 10
	// maxPacketLength = 1<<24 - 1
	MYSQL = "MySQL"
)

func init() {
	plugins.RegisterPlugin(&MYSQLPlugin{})
}

// Run checks if the identified service is a MySQL (or MariaDB) server using
// two methods. Upon the connection of a client to a MySQL server it can return
// one of two responses. Either the server returns an initial handshake packet
// or an error message packet.
func (p *MYSQLPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	mysqlVersionStr, err := CheckInitialHandshakePacket(response)
	if err == nil {
		payload := plugins.ServiceMySQL{
			PacketType:   "handshake",
			ErrorMessage: "",
			ErrorCode:    0,
		}
		return plugins.CreateServiceFrom(target, payload, false, mysqlVersionStr, plugins.TCP), nil
	}

	errorStr, errorCode, err := CheckErrorMessagePacket(response)
	if err == nil {
		payload := plugins.ServiceMySQL{
			PacketType:   "error",
			ErrorMessage: errorStr,
			ErrorCode:    errorCode,
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
	}
	return nil, nil
}

func (p *MYSQLPlugin) PortPriority(port uint16) bool {
	return port == 3306
}

func (p *MYSQLPlugin) Name() string {
	return MYSQL
}

func (p *MYSQLPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *MYSQLPlugin) Priority() int {
	return 133
}

// CheckErrorMessagePacket checks the response packet error message
func CheckErrorMessagePacket(response []byte) (string, int, error) {
	// My brief research suggests that its not possible to get a compliant
	// error message packet that is less than eight bytes
	if len(response) < 8 {
		return "", 0, &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet is too small for an error message packet",
		}
	}

	packetLength := int(
		uint32(
			response[0],
		) | uint32(
			response[1],
		)<<8 | uint32(
			response[2],
		)<<16 | uint32(
			response[3],
		)<<24,
	)
	actualResponseLength := len(response) - 4

	if packetLength != actualResponseLength {
		return "", 0, &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet length does not match length of the response from the server",
		}
	}

	header := int(response[4])
	if header != 0xff {
		return "", 0, &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet has an invalid header for an error message packet",
		}
	}

	errorCode := int(uint32(response[5]) | uint32(response[6])<<8)
	if errorCode < 1000 || errorCode > 2000 {
		return "", errorCode, &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet has an invalid error code",
		}
	}

	errorStr, err := readEOFTerminatedASCIIString(response, 7)
	if err != nil {
		return "", errorCode, &utils.InvalidResponseErrorInfo{Service: MYSQL, Info: err.Error()}
	}

	return errorStr, errorCode, nil
}

// CheckInitialHandshakePacket checks if the response received from the server
// matches the expected response for the MySQL service
func CheckInitialHandshakePacket(response []byte) (string, error) {
	// My brief research suggests that its not possible to get a compliant
	// initial handshake packet that is less than roughly 35 bytes
	if len(response) < 35 {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet length is too small for an initial handshake packet",
		}
	}

	packetLength := int(
		uint32(
			response[0],
		) | uint32(
			response[1],
		)<<8 | uint32(
			response[2],
		)<<16 | uint32(
			response[3],
		)<<24,
	)
	version := int(response[4])

	if packetLength < 25 || packetLength > 4096 {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet length doesn't make sense for the MySQL handshake packet",
		}
	}

	if version != 10 {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet has an invalid version",
		}
	}

	mysqlVersionStr, position, err := readNullTerminatedASCIIString(response, 5)
	if err != nil {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "unable to read null-terminated ASCII version string, err: " + err.Error(),
		}
	}

	// If we skip the connection id and auth-plugin-data-part-1 fields the spec says
	// there is a filler byte that should always be zero at this position
	fillerPos := position + 13
	if position >= len(response) {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "buffer is too small to be a valid initial handshake packet",
		}
	}

	// According to the specification this should always be zero since it is a filler byte
	if response[fillerPos] != 0x00 {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info: fmt.Sprintf(
				"expected filler byte at ths position to be zero got: %d",
				response[fillerPos],
			),
		}
	}

	return mysqlVersionStr, nil
}

// readNullTerminatedASCIIString is responsible for reading a null terminated
// ASCII string from a buffer and returns it as a string type
func readNullTerminatedASCIIString(buffer []byte, startPosition int) (string, int, error) {
	characters := []byte{}
	success := false
	endPosition := 0

	for position := startPosition; position < len(buffer); position++ {
		if buffer[position] >= 0x20 && buffer[position] <= 0x7E {
			characters = append(characters, buffer[position])
		} else if buffer[position] == 0x00 {
			success = true
			endPosition = position
			break
		} else {
			return "", 0, &utils.InvalidResponseErrorInfo{Service: MYSQL, Info: "encountered invalid ASCII character"}
		}
	}

	if !success {
		return "", 0, &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "hit the end of the buffer without encountering a null terminator",
		}
	}

	return string(characters), endPosition, nil
}

// readEOFTerminatedASCIIString is responsible for reading an ASCII string
// that is terminated by the end of the message
func readEOFTerminatedASCIIString(buffer []byte, startPosition int) (string, error) {
	characters := []byte{}

	for position := startPosition; position < len(buffer); position++ {
		if buffer[position] >= 0x20 && buffer[position] <= 0x7E {
			characters = append(characters, buffer[position])
		} else {
			return "", &utils.InvalidResponseErrorInfo{Service: MYSQL, Info: "encountered invalid ASCII character"}
		}
	}

	return string(characters), nil
}
