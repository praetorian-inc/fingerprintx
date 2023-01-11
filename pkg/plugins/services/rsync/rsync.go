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

package rsync

import (
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type RSYNCPlugin struct{}

const (
	RsyncMagicHeaderLength = 8
	RSYNC                  = "rsync"
)

func init() {
	plugins.RegisterPlugin(&RSYNCPlugin{})
}

func (p *RSYNCPlugin) PortPriority(port uint16) bool {
	return port == 873
}

// Run
/*
   rsync is a file synchronization protocol that can run over a number of protocols. Once
   a communication stream is set up between the sender and receiver processes, the protocol is the same, regardless
   of whether that stream is a unix pipe, an SSH connection, or a raw TCP socket. This program detects the
   presence of an rsync daemon, which detects incoming connections and forks to use a raw TCP socket. The
   rsync daemon uses no transport encryption.

   The rsync protocol is not standardized, but all implementations use a magic header "@RSYNCD:" during synchronization.

   This program was tested with docker run -p 873:873 vimagick/rsyncd
   The default port for rsyncd is 873
*/
func (p *RSYNCPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	requestBytes := []byte{
		// ascii "@RSYNCD:" magic header
		0x40, 0x52, 0x53, 0x59, 0x54, 0x43, 0x44, 0x3a,
		// space
		0x20,
		// ascii "29" client version
		0x32, 0x39,
		// newline
		0x0a,
	}

	response, err := utils.SendRecv(conn, requestBytes, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	if string(response[:RsyncMagicHeaderLength]) == "@RSYNCD:" {
		version := strings.Split(string(response[RsyncMagicHeaderLength+1:]), "\n")[0]
		return plugins.CreateServiceFrom(target, plugins.ServiceRsync{}, false, version, plugins.TCP), nil
	}

	return nil, nil
}

func (p *RSYNCPlugin) Name() string {
	return RSYNC
}

func (p *RSYNCPlugin) Type() plugins.Protocol {
	return plugins.TCP
}
func (p *RSYNCPlugin) Priority() int {
	return 578
}
