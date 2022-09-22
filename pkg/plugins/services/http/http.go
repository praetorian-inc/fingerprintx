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

package http

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type HTTPPlugin struct{}
type HTTPSPlugin struct{}

const HTTP = "http"
const HTTPS = "https"

func init() {
	plugins.RegisterPlugin(&HTTPPlugin{})
	plugins.RegisterPlugin(&HTTPSPlugin{})
}

var (
	commonHTTPPorts = map[int]struct{}{
		80:   {},
		3000: {},
		4567: {},
		5000: {},
		8000: {},
		8001: {},
		8080: {},
		8081: {},
		8888: {},
		9001: {},
		9080: {},
		9090: {},
		9100: {},
	}

	commonHTTPSPorts = map[int]struct{}{
		443:  {},
		8443: {},
		9443: {},
	}
)

func (p *HTTPPlugin) PortPriority(port uint16) bool {
	_, ok := commonHTTPPorts[int(port)]
	return ok
}

func (p *HTTPPlugin) Run(
	conn net.Conn,
	config plugins.PluginConfig,
) (*plugins.PluginResults, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s", conn.RemoteAddr().String()), nil)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil, nil
		}
		return nil, &utils.RequestError{Message: err.Error()}
	}

	// http client with custom dialier to use the provided net.Conn
	client := http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, &utils.RequestError{Message: err.Error()}
	}
	defer resp.Body.Close()
	info := map[string]any{
		"status":          resp.Status,
		"statusCode":      resp.StatusCode,
		"responseHeaders": resp.Header,
	}
	version := resp.Header.Get("Server")
	if version != "" {
		info["version"] = version
	}

	return &plugins.PluginResults{Info: info}, nil
}

func (p *HTTPSPlugin) PortPriority(port uint16) bool {
	_, ok := commonHTTPSPorts[int(port)]
	return ok
}

func (p *HTTPSPlugin) Run(
	conn net.Conn,
	config plugins.PluginConfig,
) (*plugins.PluginResults, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s", conn.RemoteAddr().String()), nil)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil, nil
		}
		return nil, &utils.RequestError{Message: err.Error()}
	}

	// https client with custom dialer to use the provided net.Conn
	client := http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, &utils.RequestError{Message: err.Error()}
	}
	defer resp.Body.Close()

	info := map[string]any{
		"status":          resp.Status,
		"statusCode":      resp.StatusCode,
		"responseHeaders": resp.Header,
	}
	version := resp.Header.Get("Server")
	if version != "" {
		info["version"] = version
	}

	return &plugins.PluginResults{Info: info}, nil
}

func (p *HTTPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *HTTPSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *HTTPPlugin) Priority() int {
	return 0
}

func (p *HTTPSPlugin) Priority() int {
	return 1
}

func (p *HTTPPlugin) Name() string {
	return HTTP
}

func (p *HTTPSPlugin) Name() string {
	return HTTPS
}
