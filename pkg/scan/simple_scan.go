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

package scan

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sort"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

var dialer = &net.Dialer{
	Timeout: 2 * time.Second,
}

var sortedTCPPlugins = make([]plugins.Plugin, 0)
var sortedTCPTLSPlugins = make([]plugins.Plugin, 0)
var sortedUDPPlugins = make([]plugins.Plugin, 0)
var tlsConfig = tls.Config{} //nolint:gosec

func init() {
	setupPlugins()
	cipherSuites := make([]uint16, 0)

	for _, suite := range tls.CipherSuites() {
		cipherSuites = append(cipherSuites, suite.ID)
	}

	for _, suite := range tls.InsecureCipherSuites() {
		cipherSuites = append(cipherSuites, suite.ID)
	}
	tlsConfig.InsecureSkipVerify = true //nolint:gosec
	tlsConfig.CipherSuites = cipherSuites
	tlsConfig.MinVersion = tls.VersionTLS10
}

func setupPlugins() {
	if len(sortedTCPPlugins) > 0 {
		// already sorted
		return
	}

	sortedTCPPlugins = append(sortedTCPPlugins, plugins.Plugins[plugins.TCP]...)
	sortedTCPTLSPlugins = append(sortedTCPTLSPlugins, plugins.Plugins[plugins.TCPTLS]...)
	sortedUDPPlugins = append(sortedUDPPlugins, plugins.Plugins[plugins.UDP]...)

	sort.Slice(sortedTCPPlugins, func(i, j int) bool {
		return sortedTCPPlugins[i].Priority() < sortedTCPPlugins[j].Priority()
	})
	sort.Slice(sortedUDPPlugins, func(i, j int) bool {
		return sortedUDPPlugins[i].Priority() < sortedUDPPlugins[j].Priority()
	})
	sort.Slice(sortedTCPTLSPlugins, func(i, j int) bool {
		return sortedTCPTLSPlugins[i].Priority() < sortedTCPTLSPlugins[j].Priority()
	})
}

// UDP Scan of the target
func (c *Config) UDPScanTarget(target plugins.Target) (*plugins.Service, error) {
	// first check the default port mappings for TCP / TLS
	for _, plugin := range sortedUDPPlugins {
		ip := target.Address.Addr().String()
		port := target.Address.Port()
		if plugin.PortPriority(port) {
			conn, err := DialUDP(ip, port)
			if err != nil {
				return nil, fmt.Errorf("unable to connect, err = %w", err)
			}
			result, err := simplePluginRunner(conn, target, c, plugin)
			if err != nil && c.Verbose {
				log.Printf("error: %v scanning %v\n", err, target.Address.String())
			}
			if result != nil && err == nil {
				return result, nil
			}
		}
	}

	// if we're fast mode, return (because fast mode only checks the default port service mapping)
	if c.FastMode {
		return nil, nil
	}

	for _, plugin := range sortedUDPPlugins {
		conn, err := DialUDP(target.Address.Addr().String(), target.Address.Port())
		if err != nil {
			return nil, fmt.Errorf("unable to connect, err = %w", err)
		}
		result, err := simplePluginRunner(conn, target, c, plugin)
		if result != nil && err == nil {
			return result, nil
		}
	}
	return nil, nil
}

// simpleScanTarget attempts to identify the service that is running on a given
// port. The fingerprinter supports two modes of operation referred to as the
// fast lane and slow lane. The fast lane aims to be as fast as possible and
// only attempts to fingerprint services by mapping them to their default port.
// The slow lane isn't as focused on performance and instead tries to be as
// accurate as possible.
func (c *Config) SimpleScanTarget(target plugins.Target) (*plugins.Service, error) {
	ip := target.Address.Addr().String()
	port := target.Address.Port()

	// first check the default port mappings for TCP / TLS
	for _, plugin := range sortedTCPPlugins {
		if plugin.PortPriority(port) {
			conn, err := DialTCP(ip, port)
			if err != nil {
				return nil, fmt.Errorf("unable to connect, err = %w", err)
			}
			result, err := simplePluginRunner(conn, target, c, plugin)
			if err != nil && c.Verbose {
				log.Printf("error: %v scanning %v\n", err, target.Address.String())
			}
			if result != nil && err == nil {
				return result, nil
			}
		}
	}

	tlsConn, tlsErr := DialTLS(target)
	isTLS := tlsErr == nil
	if isTLS {
		for _, plugin := range sortedTCPTLSPlugins {
			if plugin.PortPriority(port) {
				result, err := simplePluginRunner(tlsConn, target, c, plugin)
				if err != nil && c.Verbose {
					log.Printf("error: %v scanning %v\n", err, target.Address.String())
				}
				if result != nil && err == nil {
					// identified plugin match
					return result, nil
				}
				tlsConn, err = DialTLS(target)
				if err != nil {
					return nil, fmt.Errorf("error connecting via TLS, err = %w", err)
				}
			}
		}
	}

	// if we're fast mode, return (because fast mode only checks the default port service mapping)
	if c.FastMode {
		return nil, nil
	}

	// go through each service mapping and check it

	if isTLS {
		for _, plugin := range sortedTCPTLSPlugins {
			tlsConn, err := DialTLS(target)
			if err != nil {
				return nil, fmt.Errorf("error connecting via TLS, err = %w", err)
			}
			result, err := simplePluginRunner(tlsConn, target, c, plugin)
			if err != nil && c.Verbose {
				log.Printf("error: %v scanning %v\n", err, target.Address.String())
			}
			if result != nil && err == nil {
				// identified plugin match
				return result, nil
			}
		}
	} else {
		for _, plugin := range sortedTCPPlugins {
			conn, err := DialTCP(ip, port)
			if err != nil {
				return nil, fmt.Errorf("unable to connect, err = %w", err)
			}
			result, err := simplePluginRunner(conn, target, c, plugin)
			if err != nil && c.Verbose {
				log.Printf("error: %v scanning %v\n", err, target.Address.String())
			}
			if result != nil && err == nil {
				// identified plugin match
				return result, nil
			}
		}
	}

	return nil, nil
}

// This will attempt to close the provided Conn after running the plugin.
func simplePluginRunner(
	conn net.Conn,
	target plugins.Target,
	config *Config,
	plugin plugins.Plugin,
) (*plugins.Service, error) {
	// Log probe start.
	if config.Verbose {
		log.Printf("%v %v-> scanning %v\n",
			target.Address.String(),
			target.Host,
			plugins.CreatePluginID(plugin),
		)
	}

	result, err := plugin.Run(conn, config.DefaultTimeout, target)

	// Log probe completion.
	if config.Verbose {
		log.Printf(
			"%v %v-> completed %v\n",
			target.Address.String(),
			target.Host,
			plugins.CreatePluginID(plugin),
		)
	}
	return result, err
}

func DialTLS(target plugins.Target) (net.Conn, error) {
	config := &tlsConfig
	if target.Host != "" {
		// make a new config clone to add the custom host for each new tls connection
		c := config.Clone()
		c.ServerName = target.Host
		config = c
	}
	return tls.DialWithDialer(dialer, "tcp", target.Address.String(), config)
}

func DialTCP(ip string, port uint16) (net.Conn, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	return dialer.Dial("tcp", addr)
}

func DialUDP(ip string, port uint16) (net.Conn, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	return dialer.Dial("udp", addr)
}
