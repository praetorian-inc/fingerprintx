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
	"io/ioutil"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type HTTPPlugin struct {
	analyzer *wappalyzer.Wappalyze
}
type HTTPSPlugin struct {
	analyzer *wappalyzer.Wappalyze
}

const HTTP = "http"
const HTTPS = "https"
const USERAGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

func init() {
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		panic("unable to initialize wappalyzer library")
	}
	plugins.RegisterPlugin(&HTTPPlugin{analyzer: wappalyzerClient})
	plugins.RegisterPlugin(&HTTPSPlugin{analyzer: wappalyzerClient})
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

func (p *HTTPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s", conn.RemoteAddr().String()), nil)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil, nil
		}
		return nil, &utils.RequestError{Message: err.Error()}
	}

	if target.Host != "" {
		req.Host = target.Host
	}

	// http client with custom dialier to use the provided net.Conn
	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req.Header.Set("User-Agent", USERAGENT)

	resp, err := client.Do(req)
	if err != nil {
		return nil, &utils.RequestError{Message: err.Error()}
	}
	defer resp.Body.Close()

	technologies, _ := p.FingerprintResponse(resp)

	payload := plugins.ServiceHTTP{
		Status:          resp.Status,
		StatusCode:      resp.StatusCode,
		ResponseHeaders: resp.Header,
	}
	if len(technologies) > 0 {
		payload.Technologies = technologies
	}

	return plugins.CreateServiceFrom(target, payload, false, resp.Header.Get("Server"), plugins.TCP), nil
}

func (p *HTTPSPlugin) PortPriority(port uint16) bool {
	_, ok := commonHTTPSPorts[int(port)]
	return ok
}

func (p *HTTPSPlugin) Run(
	conn net.Conn,
	timeout time.Duration,
	target plugins.Target,
) (*plugins.Service, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s", conn.RemoteAddr().String()), nil)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil, nil
		}
		return nil, &utils.RequestError{Message: err.Error()}
	}

	if target.Host != "" {
		req.Host = target.Host
	}

	// https client with custom dialer to use the provided net.Conn
	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req.Header.Set("User-Agent", USERAGENT)

	resp, err := client.Do(req)
	if err != nil {
		return nil, &utils.RequestError{Message: err.Error()}
	}
	defer resp.Body.Close()

	technologies, _ := p.FingerprintResponse(resp)

	payload := plugins.ServiceHTTPS{
		Status:          resp.Status,
		StatusCode:      resp.StatusCode,
		ResponseHeaders: resp.Header,
	}
	if len(technologies) > 0 {
		payload.Technologies = technologies
	}

	return plugins.CreateServiceFrom(target, payload, true, resp.Header.Get("Server"), plugins.TCP), nil
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

func (p *HTTPPlugin) FingerprintResponse(resp *http.Response) ([]string, error) {
	return fingerprint(resp, p.analyzer)
}

func (p *HTTPSPlugin) FingerprintResponse(resp *http.Response) ([]string, error) {
	return fingerprint(resp, p.analyzer)
}

func fingerprint(resp *http.Response, analyzer *wappalyzer.Wappalyze) ([]string, error) {
	var technologies []string
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	fingerprint := analyzer.Fingerprint(resp.Header, data)
	for tech := range fingerprint {
		technologies = append(technologies, tech)
	}

	return technologies, nil
}
