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

package mqtt5

import (
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type MQTT5Plugin struct{}
type TLSPlugin struct{}

const MQTT = "mqtt5"
const MQTTTLS = "mqtt5tls"

func init() {
	plugins.RegisterPlugin(&MQTT5Plugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

func testConnectRequest(conn net.Conn, requestBytes []byte, timeout time.Duration) (bool, error) {
	response, err := utils.SendRecv(conn, requestBytes, timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return true, &utils.ServerNotEnable{}
	}

	if response[0] == 0x20 {
		// MQTT server
		return true, nil
	}
	return true, &utils.InvalidResponseError{Service: MQTT}
}

func (p *MQTT5Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return Run(conn, timeout, false, target)
}

func (p *MQTT5Plugin) PortPriority(i uint16) bool {
	return i == 1883
}

func (p *MQTT5Plugin) Priority() int {
	return 505
}

func (p *TLSPlugin) Priority() int {
	return 506
}

func (p *MQTT5Plugin) Name() string {
	return MQTT
}

func (p *MQTT5Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return Run(conn, timeout, true, target)
}

func (p *TLSPlugin) PortPriority(i uint16) bool {
	return i == 8883
}

func (p *TLSPlugin) Name() string {
	return MQTTTLS
}

func (p *TLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

// Run
/*
   MQTT is a publish-subscribe protocol designed to be used as
   a lightweight messaging protocol. An MQTT connection begins with
   a CONNECT request and a CONNACK response. A well-behaved MQTT server
   will simply close the connection if an invalid request is sent. Connect
   packets are formatted slightly differently between v3 and v5, so two requests
   are sent.

   CONNECT requests are composed of a fixed header that indicates the message type and
   length, and then a variable length header that specifies the connection details,
   including the protocol version. The v5 header also includes a properties section, while the
   v3 header does not.

   The CONNACK response will begin with a 0x20 byte that indicates the message type. The
   presence/absence of this byte is used to determine if MQTT is present.
*/

func Run(conn net.Conn, timeout time.Duration, tls bool, target plugins.Target) (*plugins.Service, error) {
	// version 3.1.1 connect command
	mqttConnect5 := []byte{
		// message type 1 + 4 bits reserved
		0x10,
		// message length of 18 (the number of following bytes)
		0x12,
		// protocol name length (4)
		0x00, 0x04,
		// protocol name (MQTT)
		0x4d, 0x51, 0x54, 0x54,
		// protocol version (5)
		0x05,
		// flags (all unset except for Clean Session)
		0x02,
		// keep alive
		0x00, 0x3c,
		// properties length of 0
		0x00,
		// client ID length of 5
		0x00, 0x05,
		// client ID AAAA
		0x41, 0x41, 0x41, 0x41, 0x41,
	}

	check, err := testConnectRequest(conn, mqttConnect5, timeout)
	if check && err == nil {
		return plugins.CreateServiceFrom(target, plugins.ServiceMQTT{}, tls, "5.0", plugins.TCP), nil
	} else if check && err != nil {
		return nil, nil
	}
	return nil, err
}
