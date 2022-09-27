# Plugin Structure

All service fingerprinting plugins implement the `Plugin` interface below:
```go
type Plugin interface {
	Run(net.Conn, PluginConfig) (*PluginResults, error)
	PortPriority(uint16) bool
	Name() string
	Type() Protocol
}
```

## Plugin Information

`Name()` returns the name of the service that the plugin is trying to fingerprint.

`Type()` returns the type of protocol to use for the connection to the service (TCP, TCPTLS or UDP).

`PortPriority()` returns whether the port number for the target service being fingerprinted matches a "priority" (commonly used) port number for the plugin's service. This is used for fastlane mode to speed up the fingerprinting process (specified by the `--fast`/`-f` flag for CLI usage, or specifying the "Speed" field in the "Config" for library usage).

## Running Plugin

`Run()` runs the plugin for fingerprinting the service. A network connection (`net.Conn`) is made prior to running the plugin and passed as an argument to the `Run` function, along with configuration details (`PluginConfig`) such as custom timeout values for reads/writes from/to connections.

> It is expected by design that plugins use the provided connection (`net.Conn` argument) to send/receive data for fingerprinting purposes.

## Plugin Results

If the service was found, the plugin returns a pointer to a `PluginResults` struct which contains an `Info` field storing metadata obtained while fingerprinting (if applicable):
```go
type PluginResults struct {
	Info map[string]string
}
```

If the service was not detected, the plugin returns `nil` in place of the `PluginResults` return value.

If an error was encountered while running the plugin, the plugin will return `nil` for the `PluginResults` return value, along with returning the error (in the above cases where service was found or not detected, the `error` return value should be `nil`).

> Plugins should only return an error from the `Run()` function when the plugin encounters a problem that interferes with its fingerprinting process. For example, an I/O error that is not a timeout and causes a read to fail probably does interfere with the plugin's fingerprinting process. This case should be reported as an error, as the caller failed to provide the testing environment that the plugin expected. A timeout on a UDP plugin or a 404 error for an HTTP plugin probably does not interfere with the plugin's fingerprinting process. These cases should be handled as part of the plugin's fingerprinting process as they can indicate negative results.

### Interpreting `Run` method's return values
```go
Run(net.Conn, PluginConfig) (*PluginResults, error)
```

| (PluginResults, error) | Service Detected | Service Not Detected | Error during Plugin Run |
| :-:            | :-: | :-: | :-: |
| (nil, nil)     |     |  X  |     |
| (non-nil, nil) |  X  |     |     |
| (nil, non-nil) |     |     |  X  |

> There should never be a case where the returned values of both PluginResults and error are non-nil values.


## PluginExtended Interface

Some plugins may require additional features not present in the base `Plugin` interface (e.g. [DHCP plugin](../pkg/plugins/services/dhcp/dhcp.go)). Such plugins can implement the `PluginExtended` interface (which may be expanded to add more methods to implement as needed).

```go
type PluginExtended interface {
	Plugin
	PortReject(uint16) bool
	SrcPort() uint16
	SupportedIPVersion() SupportedIPVersion
}
```

As of writing, 3 additional methods exist in the `PluginExtended` interface.

`PortReject()` can be used when a service requires a target having a specific port number, and thus a preliminary check can be performed before running the plugin to eliminate targets that have an invalid port number for the service. This method returns true if the port number is a valid port for the plugin service, and false otherwise.

`SrcPort()` can be used when a plugin requires a specific source port to be used (e.g. service may send back request to specific port number). This method should return a source port number if required, or 0 if any source port is allowed.

`SupportedIPVersion()` returns the IP version required by the target IP for the plugin (IPv4 or IPv6).


# Adding Plugins

Plugins should:
* Implement the `Plugin` interface
* Implement the `init()` function to register the plugin (using the register function in `pkg/plugins/plugins.go`)
* Import the plugin path in `pkg/scan/fingerprint.go` (this will invoke the `init()` function to run which registers the plugin)
* Plugins are expected to use the provided `Conn` for all networking connections

Example plugins can be found [here](../pkg/plugins/services) for reference.

## Plugin Helper Library

Some common utility functions exist that can be used when writing plugins via importing the `pluginutils` package.

Request functions:
* `Send(conn net.Conn, data []byte, timeout time.Duration) error`: Sends request (writes data to connection). Returns error.
* `Recv(conn net.Conn, timeout time.Duration) ([]byte, error)`: Receives response. Returns response along with error. If an error occurred but was due to timeout or connection refused, this is treated as no response being read and thus an empty slice along with a `nil` error is returned.
* `SendRecv(conn net.Conn, data []byte, timeout time.Duration) ([]byte, error)`: Combines send and receive process. Returns response along with error.

Some common errors are also defined that can be used within plugins ([reference](../pkg/plugins/pluginutils/error.go)).