# `fingerprintx scan`

The `scan` command fingerprints services over a list of hosts and specified port ranges.


## Flags

> Most flags are shared between the `target` and `scan` command. The only flags specific for the `scan` command are the `--hosts`/`-H` and `--ports`/`-p` flags.

### Scan Config

`fingerprintx scan` expects a list of hosts and corresponding port ranges to scan.

* `--hosts`/`-H`: Hosts to scan. Hosts should be specified in CIDR notation and comma-separated.
* `--ports`/`-p`: Port ranges to scan, comma-separated (e.g. "100-200,400-600,1020-1100"). All the port ranges specified are used for scanning each target host. By default, if this is flag is not set, common ports based on existing service plugins are used.
* `--timeout`/`-t`: Timeout (in milliseconds) for how long certain tasks should wait during the fingerprinting process (e.g. timeouts set on handshake process or time to wait for response to return from request). The default timeout is 500 milliseconds.
* `--max-concurrent-connections`/`-c`: Maximum number of concurrent connections to be used during the fingerprinting process (one connection is used per plugin run for a target). The default limit is 50 max concurrent connections.

### Operating Modes

By default, a `Default` operating mode is used which performs basic optimizations (in between `Slow` and `Fast` mode).

* `--fast`/`-f`: Enables fastlane mode (values speed over efficiency). Only checks mapping of default ports to default services.
* `--slow`/`-s`: Enables slowlane mode. Performs minimal optimizations during the fingerprinting process.

### Results Output

By default, results are output to standard output in the format `[protocol type]/[service]://[IP:port]` (e.g. `tcp/http://10.10.10.10:80`) for detected services. Use the JSON or CSV output format for viewing more in-depth results such as metadata collected.

* `--output`/`-o`: Output file to store results to
* `--overwrite-output`/`-F`: If the output file specified via the `--output` flag already exists (i.e. needs to be overwritten) and this flag is set, then the file will automatically be overwritten without prompting the user to confirm whether the file should be overwritten
* `--json`: Formats the results in JSON format
* `--csv`: Formats the results in CSV format

### TCP/UDP-Only Scan Options

By default, `fingerprintx` scans both TCP and UDP protocols. A user can specify only scanning TCP or UDP protocols if desired.

* `--tcp`/`-T`: Scan for TCP protocols only
* `--udp`/`-U`: Scan for UDP protocols only

### Debugging

Some optional flags exist for debugging purposes.

* `--verbose`/`-v`: Verbose mode. Prints relevant logging information to standard error.
* `--view-errors`/`-e`: Show errors occurred during plugin runs when reporting results. If this flag is not set, plugin run errors are not shown in the results.


## Example Usage

```
➜  ./fingerprintx scan -H 10.10.11.168/32 -f   
udp/dns://10.10.11.168:53
udp/ntp://10.10.11.168:123
tcp/http://10.10.11.168:80
tcp/ldap://10.10.11.168:389
tcp/mssql://10.10.11.168:1433
tcp/smb://10.10.11.168:445
tcptls/ldaps://10.10.11.168:636
```