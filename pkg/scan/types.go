package scan

import (
	"net/netip"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

type Speed int

const (
	Slow    Speed = -1
	Default Speed = 0
	Fast    Speed = 1
)

type Config struct {
	//// Target to fingerprint (IP and port pair)
	// deprecated
	Target netip.AddrPort

	// IP, UDP, TCP, or TCPTLS
	TargetProtocol plugins.Protocol

	// UDP scan
	UDP bool

	// deprecated
	Speed Speed

	FastlaneMode bool

	// The timeout value should be positive.
	// The behavior for non positive timeout values is undefined.
	// The timeout specifies how long certain tasks should wait during the scanning process.
	// This may include the timeouts set on the handshake process and the time to wait for a response to return.
	// However, the exact use of the timeout is not defined.
	DefaultTimeout time.Duration

	// deprecated
	// Specify the maximum number of conncurent connections made at a time during the scan.
	// This value must be at least 1.
	MaxConcurrentConnections uint

	// If the service is not in the map, the default timeout is used.
	TimeoutOverride map[plugins.PluginID]time.Duration

	// deprecated
	// If true, errors occurred during plugin runs are reported in the results returned
	ReportPluginErrors bool

	// deprecated
	// Only allow using unicast addresses.
	// This flag does not exclude IPv4 directed broadcast addresses.
	GlobalUnicastOnly bool

	// Prints logging messages to stderr
	Verbose bool

	// Experimental mode fields below: PacketsPerSecond, BitsPerSecond

	// deprecated
	// This value allows limiting the rate of packets sent by the scanner.
	// This value is an approximation and does not apply to all protocols.
	// This value must be at least 1.
	// deprecated
	PacketsPerSecond int
	// This value allows limiting the rate of packets sent by the scanner.
	// This value is an approximation and does not apply to all protocols.
	// This value must be at least 1.
	BitsPerSecond int
}

// either Results or Error will be nil
type ReportedResult struct {
	Addr    netip.AddrPort
	Plugin  plugins.Plugin
	Results *plugins.PluginResults
	Error   error
}
