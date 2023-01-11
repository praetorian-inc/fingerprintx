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

package modbus

import (
	"bytes"
	"crypto/rand"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

const (
	ModbusHeaderLength      = 7
	ModbusDiscreteInputCode = 0x2
	ModbusErrorAddend       = 0x80
)

type MODBUSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&MODBUSPlugin{})
}

const MODBUS = "modbus"

func (p *MODBUSPlugin) PortPriority(port uint16) bool {
	return port == 502
}

// Run
/*
   modbus is a communications standard for connecting industrial devices.
   modbus can be carried over a number of frame formats; this program identifies
   modbus over TCP.

   modbus supports diagnostic functions that could be used for fingerprinting,
   however, not all implementations will support the use of these functions.
   Therefore, this program utilizes a read primitive and validates both the success
   response and the error response conditions.

   modbus supports reading and writing to specified memory addresses using a number
   of different primitives. This program utilizes the "Read Discrete Input" primitive,
   which requests the value of a read-only boolean. This is the least likely primitive to
   be disruptive.

   Additionally, all modbus messages begin with a 7-byte header. The first two bytes are a
   client-controlled transaction ID. This program generates a random transaction ID and validates
   that the server echos the correct response.

   Initial testing done with `docker run -it -p 502:5020 oitc/modbus-server:latest`
   The default TCP port is 502, but this is unofficial.
*/
func (p *MODBUSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	transactionID := make([]byte, 2)
	_, err := rand.Read(transactionID)
	if err != nil {
		return nil, &utils.RandomizeError{Message: "Transaction ID"}
	}

	// Read Discrete Input request
	requestBytes := []byte{
		// transaction ID bytes were generated above
		// protocol ID (0)
		0x00, 0x00,
		// following byte length
		0x00, 0x06,
		// remote slave (variable, but fixed to 1 here)
		0x01,
		// function code
		0x02,
		// starting address of 0x0000
		0x00, 0x00,
		// read one bit. this will cause a successful request to return 1 byte, with the
		// 7 high bits set to zero and the low bit set to the response value
		0x00, 0x01,
	}

	requestBytes = append(transactionID, requestBytes...)

	response, err := utils.SendRecv(conn, requestBytes, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// transaction ID was echoed correctly
	if bytes.Equal(response[:2], transactionID) {
		// successful request, validate contents
		if response[ModbusHeaderLength] == ModbusDiscreteInputCode {
			if response[ModbusHeaderLength+1] == 1 && (response[ModbusHeaderLength+2]>>1) == 0x00 {
				return plugins.CreateServiceFrom(target, plugins.ServiceModbus{}, false, "", plugins.TCP), nil
			}
		} else if response[ModbusHeaderLength] == ModbusDiscreteInputCode+ModbusErrorAddend {
			return plugins.CreateServiceFrom(target, plugins.ServiceModbus{}, false, "", plugins.TCP), nil
		}
	}
	return nil, nil
}

func (p *MODBUSPlugin) Name() string {
	return MODBUS
}

func (p *MODBUSPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *MODBUSPlugin) Priority() int {
	return 400
}
