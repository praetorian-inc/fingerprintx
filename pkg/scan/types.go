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
	"net/netip"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

type Config struct {
	// IP, UDP, TCP, or TCPTLS
	TargetProtocol plugins.Protocol

	// UDP scan
	UDP bool

	FastMode bool

	// The timeout value should be positive.
	// The behavior for non positive timeout values is undefined.
	// The timeout specifies how long certain tasks should wait during the scanning process.
	// This may include the timeouts set on the handshake process and the time to wait for a response to return.
	// However, the exact use of the timeout is not defined.
	DefaultTimeout time.Duration

	// If the service is not in the map, the default timeout is used.
	TimeoutOverride map[plugins.PluginID]time.Duration

	// Prints logging messages to stderr
	Verbose bool
}

// either Results or Error will be nil
type ReportedResult struct {
	Addr    netip.AddrPort
	Plugin  plugins.Plugin
	Results *plugins.PluginResults
	Error   error
}
