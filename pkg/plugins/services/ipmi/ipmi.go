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

package ipmi

import (
	"io"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

// http://72.47.221.139/sites/default/files/standards/documents/DSP0114.pdf

var ipmiInitialPacket = [23]byte{

	//
	// Remote Management Control Protocol, Class: IPMI
	// Version:  0x06
	// Reserved: 0x00
	// Sequence: 0xFF
	// Type:     0x07
	//

	0x06, 0x00, 0xFF, 0x07,

	//
	// IPMI v1.5 Session Wrapper, Session ID 0x00
	// Authentication Type:     NONE (0x00)
	// Session ID: 0x00 0x00 0x00 0x00
	// Session Sequence number: 0x00 0x00 0x00 0x00
	// Message Length:          9
	//

	0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x09,

	//
	// Intelligent Platform Management Bus
	// Bus Command Data: 20 18 C8 81 00 38 8E 04 B5
	//

	0x20, 0x18, 0xC8, 0x81, 0x00, 0x38, 0x8E, 0x04, 0xB5,
}

var ipmiExpectedResponse = [13]byte{

	/*
	 * Remote Management Control Protocol, Class: IPMI
	 * Version:  0x06
	 * Reserved: 0x00
	 * Sequence: 0xFF
	 * Type:     0x07
	 */

	0x06, 0x00, 0xFF, 0x07,

	//
	// IPMI v1.5 Session Wrapper, Session ID 0x00
	// Authentication Type:     NONE (0x00)
	// Session ID: 0x00 0x00 0x00 0x00
	// Session Sequence number: 0x00 0x00 0x00 0x00
	//

	0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

type IPMIPlugin struct{}

const IPMI = "ipmi"

func isIPMI(conn net.Conn, timeout time.Duration) (bool, error) {
	_, err := conn.Write(ipmiInitialPacket[:])
	if err != nil {
		return false, err
	}

	response := make([]byte, len(ipmiExpectedResponse))

	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false, err
	}

	_, err = io.ReadFull(conn, response)
	if err != nil {
		return false, err
	}

	for i, b := range ipmiExpectedResponse {
		if response[i] != b {
			return false, nil
		}
	}

	return true, nil
}

func init() {
	plugins.RegisterPlugin(&IPMIPlugin{})
}

func (p *IPMIPlugin) PortPriority(port uint16) bool {
	return port == 623
}

func (p *IPMIPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	if isIPMI, err := isIPMI(conn, timeout); !isIPMI || err != nil {
		return nil, nil
	}
	payload := plugins.ServiceIPMI{}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
}

func (p *IPMIPlugin) Name() string {
	return IPMI
}

func (p *IPMIPlugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *IPMIPlugin) Priority() int {
	return 80
}
