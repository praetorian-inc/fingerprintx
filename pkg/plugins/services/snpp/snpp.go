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

package snpp

import (
	"bytes"
	"net"
	"regexp"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

// SNPP (Simple Network Paging Protocol) - RFC 1861
// Default port: 444
// The server sends a greeting upon connection, typically:
// "220 SNPP Gateway Ready" or "220 SNPP (V3) Gateway Ready"

type SNPPPlugin struct{}

const SNPP = "snpp"

// snppBannerRegex matches SNPP greeting banners with "SNPP" in the text
// The 220 code indicates the server is ready to accept commands
var snppBannerRegex = regexp.MustCompile(`^220[- ].*(?i:snpp)`)

// snpp220Regex matches any 220 response (server ready)
var snpp220Regex = regexp.MustCompile(`^220[- ]`)

// snppHelpRegex matches SNPP help response lines (214 code)
var snppHelpRegex = regexp.MustCompile(`^214[- ].*(?i:snpp)`)

func init() {
	plugins.RegisterPlugin(&SNPPPlugin{})
}

func (p *SNPPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// SNPP sends a banner upon connection, but some servers split the response
	// across multiple packets. Read until we get a complete line or hit limits.
	response := readUntilNewline(conn, timeout)

	if len(response) == 0 {
		return nil, nil
	}

	// Check for valid SNPP banner with "SNPP" in it - definitive match
	if isValidSNPPBanner(response) {
		payload := plugins.ServiceSNPP{
			Banner: string(bytes.TrimSpace(response)),
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
	}

	// Check if we got a 220 response without explicit "SNPP"
	// If so, try the HELP command to confirm
	if !snpp220Regex.Match(response) {
		return nil, nil
	}

	// Send HELP command to verify SNPP
	helpResponse, err := sendHelpCommand(conn, timeout)
	if err != nil {
		return nil, nil
	}

	// Check for 214 help response lines (characteristic of SNPP HELP output)
	if snppHelpRegex.Match(helpResponse) {
		payload := plugins.ServiceSNPP{
			Banner: string(bytes.TrimSpace(response)),
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
	}

	return nil, nil
}

func readUntilNewline(conn net.Conn, timeout time.Duration) []byte {
	var response []byte
	const maxIterations = 10

	for i := 0; i < maxIterations; i++ {
		data, err := utils.Recv(conn, timeout)
		if err != nil {
			return response
		}
		if len(data) == 0 {
			break
		}
		response = append(response, data...)

		if bytes.Contains(response, []byte("\n")) {
			break
		}
	}
	return response
}

func sendHelpCommand(conn net.Conn, timeout time.Duration) ([]byte, error) {
	// Send HELP command
	_, err := conn.Write([]byte("HELP\r\n"))
	if err != nil {
		return nil, err
	}

	// Read response - may come in multiple packets
	var response []byte
	const maxIterations = 10

	for i := 0; i < maxIterations; i++ {
		data, err := utils.Recv(conn, timeout)
		if err != nil {
			break
		}
		if len(data) == 0 {
			break
		}
		response = append(response, data...)

		// Check if we've received the end of help (259) or enough 214 lines
		if bytes.Contains(response, []byte("259")) || snppHelpRegex.Match(response) {
			break
		}
	}

	return response, nil
}

// isValidSNPPBanner checks if the response is a valid SNPP greeting
func isValidSNPPBanner(response []byte) bool {
	// Must be at least 3 bytes for the response code
	if len(response) < 3 {
		return false
	}

	// Check if it matches our SNPP banner pattern
	return snppBannerRegex.Match(response)
}

func (p *SNPPPlugin) PortPriority(port uint16) bool {
	return port == 444
}

func (p *SNPPPlugin) Name() string {
	return SNPP
}

func (p *SNPPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *SNPPPlugin) Priority() int {
	return 10
}
