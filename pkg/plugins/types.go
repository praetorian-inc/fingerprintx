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
