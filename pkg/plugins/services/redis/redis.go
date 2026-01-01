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

package redis

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type REDISPlugin struct{}
type REDISTLSPlugin struct{}

type Info struct {
	AuthRequired bool
}

const REDIS = "redis"
const REDISTLS = "redis"

// Check if the response is from a Redis server
// returns an error if it's not validated as a Redis server
// and a Info struct with AuthRequired if it is
func checkRedis(data []byte) (Info, error) {
	// a valid pong response will be the 7 bytes [+PONG(CR)(NL)]
	pong := [7]byte{0x2b, 0x50, 0x4f, 0x4e, 0x47, 0x0d, 0x0a}
	// an auth error will start with the 7 bytes: [-NOAUTH]
	noauth := [7]byte{0x2d, 0x4e, 0x4f, 0x41, 0x55, 0x54, 0x48}

	msgLength := len(data)
	if msgLength < 7 {
		return Info{}, &utils.InvalidResponseErrorInfo{
			Service: REDIS,
			Info:    "too short of a response",
		}
	}

	if msgLength == 7 {
		if bytes.Equal(data, pong[:]) {
			// Valid PONG response means redis server and no auth
			return Info{AuthRequired: false}, nil
		}
		return Info{}, &utils.InvalidResponseErrorInfo{
			Service: REDIS,
			Info:    "invalid PONG response",
		}
	}
	if !bytes.Equal(data[:7], noauth[:]) {
		return Info{}, &utils.InvalidResponseErrorInfo{
			Service: REDIS,
			Info:    "invalid Error response",
		}
	}

	return Info{AuthRequired: true}, nil
}

// extractRedisVersion extracts the Redis version from an INFO SERVER response.
// The INFO command returns a bulk string in RESP format containing key-value pairs.
// Each line is in the format "key:value\r\n" and we look for the "redis_version" field.
//
// Parameters:
//   - response: The INFO SERVER response string containing server metadata
//
// Returns:
//   - string: The Redis version (e.g., "7.4.0"), or empty string if not found
func extractRedisVersion(response string) string {
	if response == "" {
		return ""
	}

	// Split response by newlines (either \r\n or \n)
	lines := strings.Split(strings.ReplaceAll(response, "\r\n", "\n"), "\n")

	// Look for redis_version field
	for _, line := range lines {
		if strings.HasPrefix(line, "redis_version:") {
			// Extract version after the colon
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	return ""
}

// buildRedisCPE generates a CPE (Common Platform Enumeration) string for Redis servers.
// CPE format: cpe:2.3:a:redis:redis:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" wildcard to match Wappalyzer/RMI/FTP plugin behavior
// and enable asset inventory use cases even without precise version information.
//
// Parameters:
//   - version: Redis version string (e.g., "7.4.0"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" wildcard
func buildRedisCPE(version string) string {
	// Use wildcard for unknown versions (matches FTP/RMI/Wappalyzer pattern)
	if version == "" {
		version = "*"
	}

	// Redis CPE template: cpe:2.3:a:redis:redis:{version}:*:*:*:*:*:*:*
	return fmt.Sprintf("cpe:2.3:a:redis:redis:%s:*:*:*:*:*:*:*", version)
}

func init() {
	plugins.RegisterPlugin(&REDISPlugin{})
	plugins.RegisterPlugin(&REDISTLSPlugin{})
}

func (p *REDISPlugin) PortPriority(port uint16) bool {
	return port == 6379
}

func (p *REDISTLSPlugin) PortPriority(port uint16) bool {
	return port == 6380
}

func (p *REDISTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return DetectRedis(conn, target, timeout, true)
}

func DetectRedis(conn net.Conn, target plugins.Target, timeout time.Duration, tls bool) (*plugins.Service, error) {
	//https://redis.io/commands/ping/
	// PING is a supported command since 1.0.0
	// [*1(CR)(NL)$4(CR)(NL)PING(CR)(NL)]
	ping := []byte{
		0x2a,
		0x31,
		0x0d,
		0x0a,
		0x24,
		0x34,
		0x0d,
		0x0a,
		0x50,
		0x49,
		0x4e,
		0x47,
		0x0d,
		0x0a,
	}

	response, err := utils.SendRecv(conn, ping, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	result, err := checkRedis(response)
	if err != nil {
		return nil, nil
	}

	// Phase 2: Enrichment - Try to extract version via INFO SERVER
	// This may fail if authentication is required, but detection still succeeds
	version := ""
	if !result.AuthRequired {
		// INFO SERVER command in RESP format
		// [*2(CR)(NL)$4(CR)(NL)INFO(CR)(NL)$6(CR)(NL)SERVER(CR)(NL)]
		infoCmd := []byte{
			0x2a, 0x32, 0x0d, 0x0a, // *2\r\n
			0x24, 0x34, 0x0d, 0x0a, // $4\r\n
			0x49, 0x4e, 0x46, 0x4f, 0x0d, 0x0a, // INFO\r\n
			0x24, 0x36, 0x0d, 0x0a, // $6\r\n
			0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x0d, 0x0a, // SERVER\r\n
		}

		// Try to get INFO response (may fail gracefully)
		infoResp, err := utils.SendRecv(conn, infoCmd, timeout)
		if err == nil && len(infoResp) > 0 {
			// Parse RESP bulk string format: $<length>\r\n<data>\r\n
			// Extract the data portion and parse version
			if len(infoResp) > 2 && infoResp[0] == '$' {
				// Find the first \r\n (end of length prefix)
				for i := 1; i < len(infoResp)-1; i++ {
					if infoResp[i] == '\r' && infoResp[i+1] == '\n' {
						// Data starts after \r\n
						dataStart := i + 2
						if dataStart < len(infoResp) {
							infoData := string(infoResp[dataStart:])
							version = extractRedisVersion(infoData)
						}
						break
					}
				}
			}
		}
	}

	// Generate CPE (uses "*" for unknown version)
	cpe := buildRedisCPE(version)

	payload := plugins.ServiceRedis{
		AuthRequired: result.AuthRequired,
		CPEs:         []string{cpe},
	}
	if tls {
		return plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS), nil
	}
	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *REDISPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return DetectRedis(conn, target, timeout, false)
}

func (p *REDISPlugin) Name() string {
	return REDIS
}

func (p *REDISTLSPlugin) Name() string {
	return REDISTLS
}

func (p *REDISPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *REDISTLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *REDISPlugin) Priority() int {
	return 413
}

func (p *REDISTLSPlugin) Priority() int {
	return 414
}
