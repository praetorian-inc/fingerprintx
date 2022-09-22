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

package plugins

import (
	"net"
	"time"
)

type SupportedIPVersion uint64
type Protocol uint64

const (
	IP Protocol = iota + 1
	UDP
	TCP
	TCPTLS
)

const (
	IPv4 SupportedIPVersion = 1 << iota
	IPv6
)

// Used as a key for maps to plugins.
// i.e.: map[Service] Plugin
type PluginID struct {
	name     string
	protocol Protocol
}

type PluginConfig struct {
	Timeout time.Duration
}

type PluginResults struct {
	Info map[string]any
}

type Plugin interface {
	// If the PluginResults != nil, and error == nil the service was found
	// If the PluginResults == nil, and error == nil the service was not found
	// If the PluginResults == nil, and error != nil an error was encountered while looking for the plugin
	// Never return both PluginResults and error as not nil
	Run(net.Conn, PluginConfig) (*PluginResults, error)
	PortPriority(uint16) bool
	Name() string
	Type() Protocol
	Priority() int
}

type PluginExtended interface {
	Plugin

	// Return true if the dst port must be skipped
	PortReject(uint16) bool

	// Return 0 if any src port is allowed
	SrcPort() uint16

	SupportedIPVersion() SupportedIPVersion
}
