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

package ntp

import (
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

const NTP = "ntp"

type Plugin struct{}

var ModeServer uint8 = 4

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// reference: https://datatracker.ietf.org/doc/html/rfc5905#section-7.3
	InitialConnectionPackage := []byte{
		0xe3, 0x00, 0x0a, 0xf8, // LI/VN/Mode | Stratum | Poll | Precision
		0x00, 0x00, 0x00, 0x00, // Root Delay
		0x00, 0x00, 0x00, 0x00, // Root Dispersion
		0x00, 0x00, 0x00, 0x00, // Reference Identifier
		0x00, 0x00, 0x00, 0x00, // Reference Timestamp
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // Origin Timestamp
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // Receive Timestamp
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // Transmit Timestamp
		0x00, 0x00, 0x00, 0x00,
	}

	response, err := utils.SendRecv(conn, InitialConnectionPackage, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// check if response is valid NTP packet
	if response[0]&0x07 == ModeServer && len(response) == len(InitialConnectionPackage) {
		return plugins.CreateServiceFrom(target, plugins.ServiceNTP{}, false, "", plugins.UDP), nil
	}
	return nil, nil
}

func (p *Plugin) PortPriority(i uint16) bool {
	return i == 123
}

func (p *Plugin) Name() string {
	return NTP
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 800
}
