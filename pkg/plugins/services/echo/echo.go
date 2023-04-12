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

package echo

import (
	"bytes"
	"crypto/rand"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type EchoPlugin struct{}

const ECHO = "echo"

func isEcho(conn net.Conn, timeout time.Duration) (bool, error) {
	// Generate a random 64 byte payload
	payload := make([]byte, 64)
	if _, err := rand.Read(payload); err != nil {
		return false, err
	}

	response, err := pluginutils.SendRecv(conn, payload, timeout)
	if err != nil {
		return false, err
	}

	// Check if the response matches the payload
	isEchoService := bytes.Equal(payload, response)

	return isEchoService, nil
}

func init() {
	plugins.RegisterPlugin(&EchoPlugin{})
}

func (p *EchoPlugin) PortPriority(port uint16) bool {
	return port == 7
}

func (p *EchoPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	if isEcho, err := isEcho(conn, timeout); !isEcho || err != nil {
		return nil, nil
	}
	payload := plugins.ServiceEcho{}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

func (p *EchoPlugin) Name() string {
	return ECHO
}

func (p *EchoPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *EchoPlugin) Priority() int {
	return 1
}
