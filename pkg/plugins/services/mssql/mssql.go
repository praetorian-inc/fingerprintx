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

package mssql

import (
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

// Potential values for PLOptionToken
const (
	VERSION         int  = 0
	ENCRYPTION      int  = 1
	INSTOPT         int  = 2
	THREADID        int  = 3
	MARS            int  = 4
	TRACEID         int  = 5
	FEDAUTHREQUIRED int  = 6
	NONCEOPT        int  = 7
	TERMINATOR      byte = 0xFF
)

type OptionToken struct {
	PLOptionToken  uint32
	PLOffset       uint32
	PLOptionLength uint32
	PLOptionData   []byte // the raw data associated with the option
}

type MSSQLPlugin struct{}

type Data struct {
	Version string
}

const MSSQL = "mssql"

func init() {
	plugins.RegisterPlugin(&MSSQLPlugin{})
}

func (p *MSSQLPlugin) PortPriority(port uint16) bool {
	return port == 1433
}

func DetectMSSQL(conn net.Conn, timeout time.Duration) (Data, bool, error) {
	// Below is a TDS prelogin packet sent by the client to begin the
	// initial handshake with the server
	preLoginPacket := []byte{

		// Pre-Login Request Header
		0x12,       // Type
		0x01,       // Status
		0x00, 0x58, // Length
		0x00, 0x00, // SPID
		0x01, // PacketID
		0x00, // Window

		// We configure the following options within the pre-login request body:
		//
		// VERSION:        11 09 00 01 00 00
		// ENCRYPTION:     00
		// INSTOPT:        00
		// THREADID:       00 00 00 00
		// MARS:           00
		// TRACEID:        f9 b8 cb 5c 94 6b 89 1f
		//                 d9 aa 3c 13 4b d0 7b 88
		//                 03 5c 32 21 24 a2 81 86
		//                 37 cf 62 39 4a 46 2c c6
		//                 00 00 00 00

		// Pre-Login Request Payload
		0x00,       // PLOptionToken (VERSION)
		0x00, 0x1F, // PLOffset
		0x00, 0x06, // PLOptionLength

		0x01,       // PLOptionToken (ENCRYPTION)
		0x00, 0x25, // PLOffset
		0x00, 0x01, // PLOptionLength

		0x02,       // PLOptionToken (INSTOPT)
		0x00, 0x26, // PLOffset
		0x00, 0x01, // PLOptionLength

		0x03,       // PLOptionToken (THREADID)
		0x00, 0x27, // PLOffset
		0x00, 0x04, // PLOptionLength

		0x04,       // PLOptionToken (MARS)
		0x00, 0x2B, // PLOffset
		0x00, 0x01, // PLOptionLength

		0x05,       // PLOptionToken (TRACEID)
		0x00, 0x2C, // PLOffset
		0x00, 0x24, // PLOptionLength

		0xFF, // TERMINATOR

		// PLOptionData
		0x11, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0xF9, 0xB8, 0xCB,
		0x5C, 0x94, 0x6B, 0x89, 0x1F, 0xD9, 0xAA, 0x3C,
		0x13, 0x4B, 0xD0, 0x7B, 0x88, 0x03, 0x5C, 0x32,
		0x21, 0x24, 0xA2, 0x81, 0x86, 0x37, 0xCF, 0x62,
		0x39, 0x4A, 0x46, 0x2C, 0xC6, 0x00, 0x00, 0x00,
		0x00,
	}

	response, err := utils.SendRecv(conn, preLoginPacket, timeout)
	if err != nil {
		return Data{}, false, err
	}
	if len(response) == 0 {
		return Data{}, true, &utils.ServerNotEnable{}
	}

	/*
		Below is an example pre-login response (tabular response) packet
		returned by the client to the server:

			Pre-Login Response (Tabular Response) Header:

			Type:     0x04
			Status:   0x01
			Length:   0x00 0x30
			SPID:     0x00 0x00
			PacketId: 0x01
			Window:   0x00

			Pre-Login Response Body:

			PLOptionToken:  0x00 (VERSION)
			PLOffset:        0x00 0x1F
			PLOptionLength: 0x00 0x06

			PLOptionToken:  0x01 (ENCRYPTION)
			PLOffset:        0x00 0x25
			PLOptionLength: 0x00 0x01

			PLOptionToken:  0x02 (INSTOPT)
			PLOffset:        0x00 0x26
			PLOptionLength: 0x00 0x01

			PLOptionToken:  0x03 (THREADID)
			PLOffset:        0x00 0x27
			PLOptionLength: 0x00 0x00

			PLOptionToken:  0x04 (MARS)
			PLOffset:        0x00 0x27
			PLOptionLength: 0x00 0x01

			PLOptionToken:  0x05 (TRACEID)
			PLOffset:        0x00 0x28
			PLOptionLength: 0x00 0x00

			PLOptionToken:  0xFF

			PLOptionData:   0f 00 07 d0 00 00 00 00 00

			VERSION:    0f 00 07 d0 00 00
			ENCRYPTION: 00
			INSTOPT     00
			MARS:       00
	*/

	// The TDS header is eight bytes so any response less than this can be safely classified
	// as invalid (i.e. not MSSQL/TDS)
	if len(response) < 8 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "response is too short to be a valid TDS packet header",
		}
	}

	if response[0] != 0x04 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "type should be set to tabular result for a valid TDS packet",
		}
	}

	if response[1] != 0x01 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "expect a status of one (end of message) for tabular result packet",
		}
	}

	packetLength := int(uint32(response[3]) | uint32(response[2])<<8)
	if len(response) != packetLength {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "packet length does not match length read",
		}
	}

	if response[4] != 0x00 || response[5] != 0x00 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "value for SPID should always be zero",
		}
	}

	if response[6] != 0x01 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "value for packet id should always be one",
		}
	}

	if response[7] != 0x00 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "value for window should always be zero",
		}
	}

	// The body of the pre-login response message is a list of PL_OPTION tokens
	// that index into the PLOptionData segment and the list is
	// terminated by a PLOptionToken with TERMINATOR (0xFF) as the value.

	position := 8 // set to the position to just after the TDS packet header

	var optionTokens []OptionToken
	for response[position] != TERMINATOR && position < len(response) {
		plOptionToken := uint32(response[position+0])
		plOffset := uint32(response[position+2]) | uint32(response[position+1])<<8
		plOptionLength := uint32(response[position+4]) | uint32(response[position+3])<<8

		plOptionData := []byte{}
		if plOptionLength != 0 {
			if plOffset+plOptionLength < uint32(len(response)) {
				plOptionData = response[plOffset+8 : plOffset+8+plOptionLength]
			} else {
				return Data{}, true, &utils.InvalidResponseErrorInfo{
					Service: MSSQL,
					Info:    "server returned an invalid PLOffset or PLOptionLength"}
			}
		}

		position += 5
		optionTokenStruct := OptionToken{
			PLOptionToken:  plOptionToken,
			PLOffset:       plOffset,
			PLOptionLength: plOptionLength,
			PLOptionData:   plOptionData,
		}

		optionTokens = append(optionTokens, optionTokenStruct)
	}

	if response[position] != 0xFF {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "list of option tokens should be terminated by 0xff",
		}
	}

	if len(optionTokens) < 1 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "there should be at least one option token since VERSION is required",
		}
	}

	if optionTokens[0].PLOptionToken != 0x00 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "TDS requires VERSION to be the first PLOptionToken value",
		}
	}

	if optionTokens[0].PLOptionLength != 0x06 {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: MSSQL,
			Info:    "version field should be fixed bytes",
		}
	}

	MajorVersion := optionTokens[0].PLOptionData[0]
	MinorVersion := optionTokens[0].PLOptionData[1]
	BuildNumber := uint32(
		(uint32(optionTokens[0].PLOptionData[2]) * 256) + uint32(
			optionTokens[0].PLOptionData[3],
		),
	)

	version := fmt.Sprintf("%d.%d.%d\n", MajorVersion, MinorVersion, BuildNumber)

	return Data{Version: version}, true, nil
}

func (p *MSSQLPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	data, check, err := DetectMSSQL(conn, timeout)
	if check && err != nil {
		return nil, nil
	} else if !check && err != nil {
		return nil, err
	}

	return plugins.CreateServiceFrom(target, plugins.ServiceMSSQL{}, false, data.Version, plugins.TCP), nil
}

func (p *MSSQLPlugin) Name() string {
	return MSSQL
}

func (p *MSSQLPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *MSSQLPlugin) Priority() int {
	return 143
}
