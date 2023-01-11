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

package netbios

import (
	"crypto/rand"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

const NETBIOS = "netbios-ns"

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	transactionID := make([]byte, 2)
	_, err := rand.Read(transactionID)
	if err != nil {
		return nil, &utils.RandomizeError{Message: "Transaction ID"}
	}
	InitialConnectionPackage := append(transactionID, []byte{ //nolint:gocritic
		// Transaction ID
		0x00, 0x10, // Flag: Broadcast
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Queries
		0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
		0x00, 0x21,
		0x00, 0x01,
	}...)

	response, err := utils.SendRecv(conn, InitialConnectionPackage, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	stringBegin := strings.Index(string(response), "\x00\x00\x00\x00\x00") + 7
	stringEnd := strings.Index(string(response), "\x20\x20\x20")
	if stringBegin == -1 || stringEnd == -1 || stringEnd < stringBegin ||
		stringBegin >= len(response) || stringEnd >= len(response) {
		return nil, nil
	}
	payload := plugins.ServiceNetbios{
		NetBIOSName: string(response[stringBegin:stringEnd]),
	}
	return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
}

func (p *Plugin) PortPriority(i uint16) bool {
	return i == 137
}

func (p *Plugin) Name() string {
	return NETBIOS
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 700
}
