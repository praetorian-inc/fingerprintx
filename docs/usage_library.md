# Using `fingerprintx` as a Library

## API

`fingerprintx` provides 3 library functions for use in applications where fingerprinting functionality is needed. These functions can be accessed by importing the `scan` package located in `pkg/scan`.

```go
Fingerprint(config Config) ([]ReportedResult, error)

Scan(ips []netip.Prefix, ports []utils.PortRange, config Config) ([]ReportedResult, error)

ScanTargets(targets []netip.AddrPort, config Config) ([]ReportedResult, error)
```

`Fingerprint` performs port fingerprinting on a single target (IP+port pair).

`Scan` performs port fingerprinting on a list of host networks and port range. This function's functionality is identical to `fingerprintx`'s `scan` command.

`ScanTargets` performs port fingerprinting on a list of targets (IP+port pairs). This function's functionality is identical to `fingerprintx`'s `target` command.

## Configuration

All API functions require passing in a configuration of type `Config`:
```go
type Config struct {
  Target                    netip.AddrPort
  TargetProtocol            plugins.Protocol
  Speed                     Speed
  DefaultTimeout            time.Duration
  MaxConcurrentConnections  uint
  TimeoutOverride           map[plugins.PluginID]time.Duration
  ReportPluginErrors        bool
  GlobalUnicastOnly         bool
  Verbose                   bool
}
```

* `Target` (Required for `Fingerprint` only): This field only needs to be specified when using the `Fingerprint` function.
* `TargetProtocol` (Required): This field specifies the protocol type to fingerprint (protocol types are defined in the `plugins` package in `pkg/plugins`). As of writing, 4 different protocol types are supported: `IP`, `UDP`, `TCP`, and `TCPTLS`. `IP` encompasses both `TCP` and `UDP` protocols (most generic option). `TCPTLS` is a subset of the `TCP` protocol that only includes protocols that support TLS.
* `Speed`: This field specifies the operating mode for fingerprinting. 3 different speed modes are supported: Fast, Slow, Default (defined in the `scan` package in `pkg/scan`). Fast mode can be set for faster fingerprinting, only checking mapping of default ports to default services. Slow mode can be set for valuing accuracy over speed, performing minimal optimizations during the fingerprinting process. By default, Default mode is used for this field (which performs basic optimizations, in between Slow and Fast mode with regards to speed).
* `DefaultTimeout` (Required): This field specifies the timeout for how long certain tasks should wait during the scanning process (e.g. timeouts set on handshake process or time to wait for response to return from request). The time must be a positive duration.
* `MaxConcurrentConnections` (Required): This field specifies the maximum number of concurrent connections made at a time during the scan (each connection corresponds to a service plugin run for a given target). This value must be at least 1.
* `TimeoutOverride`: This field allows specifying timeout values for specific service plugins to use. If the service is not in the `TimeoutOverride` map, the default timeout specified in `DefaultTimeout` is used.
* `ReportPluginErrors`: If this field is set to true, errors that occurred durin service plugin runs are reported in the results. By default, plugin errors are not included in the results.
* `GlobalUnicastOnly`: If this field is true, only unicast addresses are scanned (note: IPv4 directed broadcast addresses are still scanned). By default, all addresses (unicast, multicast, broadcast) addresses are scanned.

> The `Verbose` field is used primarily by the CLI tool for specifying whether logging messages should be printed to standard error. This field is likely not useful if using Fingerprintx as a library and can be ignored.

## Fingerprint Results

All API functions return the results in a list of `ReportedResult` values. A result is reported by a plugin only if 1) the service was detected or 2) an error occurred while running the plugin.

```go
type ReportedResult struct {
  Addr    netip.AddrPort
  Plugin  plugins.Plugin
  Results *plugins.PluginResults
  Error   error
}
```

* `Addr`: The target's IP and port
* `Plugin`: The service plugin reporting the result (`Plugin` type is defined in the `plugins` package in `pkg/plugins`). `Plugin.Name()` can be used to return the service name for the plugin and `Plugin.Type()` can be used to return the protocol type (e.g. TCP, UDP) for the plugin.
* `Results`: Results from fingerprinting. The `PluginResults` struct contains an `Info` field (of type `map[string]any`) which stores any metadata collected during the fingerprinting process such as version information, etc.
* `Error`: If an error occurred while running the plugin (i.e. plugin encountered a problem that interfered with its fingerprinting process) and the `ReportPluginErrors` field is set to true in the configuration for the run, then the error is stored in this field for reporting purposes.

> NOTE: One of `Results` or `Error` should be a nil value and the other a non-nil value.

## Example

An example Go program using the Fingerprintx library is below:
```go
package main

import (
  "fmt"
  "net/netip"
  "os"
  "time"

  "github.com/praetorian-inc/fingerprintx/pkg/scan"
  "github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

func main() {
  target, err := netip.ParseAddrPort("10.10.11.168:123")
  if err != nil {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(1)
  }

  config := scan.Config{
    Target: target,
    TargetProtocol: plugins.IP,
    Speed: scan.Fast,
    DefaultTimeout: 500 * time.Millisecond,
    MaxConcurrentConnections: 50,
  }

  results, err := scan.Fingerprint(config)
  if err != nil {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(1)
  }

  for _, result := range results {
    fmt.Println("Detected", result.Plugin.Name())
  }
}
```