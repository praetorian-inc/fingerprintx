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
	"net/netip"
	"sort"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

type pluginPanicError struct {
	config Config
	plugin plugins.Plugin
	err    any
}

func (w *pluginPanicError) Error() string {
	return fmt.Sprintf(
		"Plugin %v panicked: %v",
		plugins.CreatePluginID(w.plugin),
		w.err,
	)
}

var dialer = &net.Dialer{
	Timeout: 3 * time.Second,
}

var sortedTCPPlugins = make([]plugins.Plugin, 0)
var sortedTCPTLSPlugins = make([]plugins.Plugin, 0)
var sortedUDPPlugins = make([]plugins.Plugin, 0)

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
func (c *Config) UDPScanTarget(target netip.AddrPort) (ReportedResult, error) {
	setupPlugins()

	for _, plugin := range sortedUDPPlugins {
		conn, err := DialUDP(target.Addr().String(), target.Port())
		if err != nil {
			return ReportedResult{}, fmt.Errorf("unable to connect, err = %w", err)
		}
		result := simplePluginRunner(conn, target, c, plugin)
		if result.Results != nil {
			return result, nil
		}
	}
	return ReportedResult{}, nil
}

// simpleScanTarget attempts to identify the service that is running on a given
// port. The fingerprinter supports two modes of operation referred to as the
// fast lane and slow lane. The fast lane aims to be as fast as possible and
// only attempts to fingerprint services by mapping them to their default port.
// The slow lane isn't as focused on performance and instead tries to be as
// accurate as possible.
func (c *Config) simpleScanTarget(target netip.AddrPort, fastMode bool) (ReportedResult, error) {
	ip := target.Addr().String()
	port := target.Port()
	setupPlugins()

	// Some services leverage TCP and TLS services on the
	// same port. This causes a weird bug with certain services like RDP
	// where the handshake seems to be different when TLS is leveraged. We
	// will eventually properly fingerprint the service in the slow lane,
	// but only after calling back to TCP plugins and running all the
	// corresponding TLS plugins. This is a hack to get around this edge
	// case as an optimization.
	//
	// If the port has multiple default mappings we only run the first one
	// so in some cases we still bail out to the slow path.
	if fastMode {
		for _, plugin := range sortedTCPPlugins {
			if plugin.PortPriority(port) {
				conn, err := DialTCP(ip, port)
				if err != nil {
					return ReportedResult{}, fmt.Errorf("unable to connect, err = %w", err)
				}
				result := simplePluginRunner(conn, target, c, plugin)
				if result.Results != nil {
					return result, nil
				}
			}
		}
	}

	// We attempt an initial TLS connection to the target port to
	// determine if the service running on that port leverages TLS as a
	// transport. If this is true we can exclude all plugins that don't
	// support TLS as an optimization.

	tlsConn, err := DialTLS(ip, port)
	isTLS := err == nil
	if isTLS {
		for _, plugin := range sortedTCPTLSPlugins {
			// If we are running in fast mode we only invoke a plugin if it registers
			// itself as being the one of the default services
			// associated with this port. In slow, mode we need to
			// run every registered plugin.
			if plugin.PortPriority(port) || !fastMode {
				// Invoke the plugin and return the discovered service event if
				// we are successful
				result := simplePluginRunner(tlsConn, target, c, plugin)
				if result.Results != nil {
					// identified plugin match
					return result, nil
				}

				// Unfortunately, if we run a plugin and it fails we have to create an entirely
				// new TLS connection in order to invoke the next plugin.
				tlsConn, err = DialTLS(ip, port)
				if err != nil {
					return ReportedResult{}, fmt.Errorf("error connecting via TLS, err = %w", err)
				}
			}
		}
		// If we fail to fingerprint the service in fast lane we just bail out to the
		// slow lane. However, in the slow lane we want to also try the TCP plugins
		// just to be safe.
		if fastMode {
			return ReportedResult{}, nil
		}
	}

	for _, plugin := range sortedTCPPlugins {
		// In fast mode we only run the corresponding TCP port plugin if it is
		// associated with the default port for the service. Within the slow path
		// we run every plugin regardless of the default port mapping.
		if plugin.PortPriority(port) || !fastMode {
			conn, err := DialTCP(ip, port)
			if err != nil {
				return ReportedResult{}, fmt.Errorf("unable to connect, err = %w", err)
			}
			result := simplePluginRunner(conn, target, c, plugin)
			if result.Results != nil {
				// identified plugin match
				return result, nil
			}
		}
	}

	return ReportedResult{}, nil
}

// This will attempt to close the provided Conn after running the plugin.
func simplePluginRunner(
	conn net.Conn,
	target netip.AddrPort,
	config *Config,
	plugin plugins.Plugin,
) ReportedResult {
	// Log probe start.
	if config.Verbose {
		log.Printf(
			"%v -> scanning  %v\n",
			target.String(),
			plugins.CreatePluginID(plugin),
		)
	}
	pluginConfig := config.GeneratePluginConfig(plugin)

	// Call the Run method on the plugin.
	// This needs to be in a function to handle panics.
	result, err := func(
		config *Config,
		plugin plugins.Plugin,
		conn net.Conn,
		pluginConfig plugins.PluginConfig,
	) (result *plugins.PluginResults, err error) {
		var panicked = true
		defer func(panicked *bool, config Config, plugin plugins.Plugin) {
			if *panicked {
				result = nil
				err = &pluginPanicError{config: config, plugin: plugin, err: recover()}
			}
		}(&panicked, *config, plugin)
		result, err = plugin.Run(conn, pluginConfig)
		// If we get here, the Run method did not panic.
		panicked = false
		return result, err
	}(config, plugin, conn, pluginConfig)

	// Log probe completion.
	if config.Verbose {
		log.Printf(
			"%v -> completed %v\n",
			target.String(),
			plugins.CreatePluginID(plugin),
		)
	}

	// Report result.
	return ReportedResult{Addr: target, Plugin: plugin, Results: result, Error: err}
}

func DialTLS(ip string, port uint16) (net.Conn, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec
	return conn, err
}

func DialTCP(ip string, port uint16) (net.Conn, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	return dialer.Dial("tcp", addr)
}

func DialUDP(ip string, port uint16) (net.Conn, error) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	return dialer.Dial("udp", addr)
}
