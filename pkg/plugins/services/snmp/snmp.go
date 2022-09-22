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

package snmp

import (
	"bytes"
	"net"
	"strings"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

const SNMP = "SNMP"

type SNMPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&SNMPPlugin{})
}

func (f *SNMPPlugin) Run(conn net.Conn, config plugins.PluginConfig) (*plugins.PluginResults, error) {
	RequestID := []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	InitialConnectionPackage := []byte{
		0x30, 0x29, // package length
		0x02, 0x01, 0x00, // Version: 1
		0x04, 0x06, // Community
		0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // method: "public"
		0xa0, // PDU type: GET
		0x1c,
		0x02, 0x04, 0xff, 0xff, 0xff, 0xff, // Request ID: -1
		0x02, 0x01, 0x00, // Error status: no error
		0x02, 0x01, 0x00, // Error index
		0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, // Object ID
		0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
	}
	InfoOffset := 33

	response, err := utils.SendRecv(conn, InitialConnectionPackage, config.Timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	idx := strings.Index(string(response), "public")
	if idx == -1 {
		return nil, nil
	}
	stringBegin := idx + InfoOffset
	if bytes.Contains(response, RequestID) {
		info := map[string]any{"version": string(response[stringBegin:])}
		return &plugins.PluginResults{Info: info}, nil
	}
	return nil, nil
}

/*func (f *SNMPPlugin) checkVersion(conn net.Conn, config plugins.PluginConfig) (*plugins.PluginResults, error) {
	InitialConnectionPackage := []byte{
		0x30, 0x3a, // package length
		0x02, 0x01, 0x03, // Version: 3
		0x30, 0x0f, 0x02, 0x02, 0x00, 0x00, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x00, 0x02, 0x01, 0x03,
		0x04, 0x10, 0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00,
		0x30, 0x12, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0c, 0x02, 0x02,
		0xff, 0xff, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
	}

	err = utils.Send(conn, InitialConnectionPackage, config.Timeout)
	if err != nil {
		return nil, err
	}

	response, err := utils.Recv(conn, config.Timeout)
	if err != nil {
		return nil, err
	}

	signature := int64(response[64])<<8 + int64(response[65])
	return &plugins.PluginResults{Info: strconv.FormatInt(signature, 10)}, nil
}*/

func (f *SNMPPlugin) Name() string {
	return SNMP
}

func (f *SNMPPlugin) PortPriority(i uint16) bool {
	return i == 161
}

func (f *SNMPPlugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (f *SNMPPlugin) Priority() int {
	return 81
}
