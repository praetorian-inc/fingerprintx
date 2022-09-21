# `fingerprintx target`

The `target` command fingerprints services given a list of target host/port pairs via file or piped standard input. It is intended to be used alongside existing tools, taking in an input format that other tools can leverage such as [Naabu](https://github.com/projectdiscovery/naabu).


## Flags

> Most flags are shared between the `target` and `scan` command. The only flag specific for the `target` command is the `--list`/`-l` flag.

### Scan Config

By default, `fingerprintx target` expects a list of target host/port pairs separated by newlines passed in via standard input (if an input file isn't specified via the `--list` flag). Hosts can be IP addresses or subdomains.

* `--list`/`-l`: Input file containing a list of target host/port pairs separated by newlines
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
➜  echo 10.10.11.168 | naabu -silent | ./fingerprintx target -f
udp/dns://10.10.11.168:53
tcp/mssql://10.10.11.168:1433
tcp/ldap://10.10.11.168:389
tcp/http://10.10.11.168:80
tcp/smb://10.10.11.168:445
```

```
➜  echo 10.10.11.168 | naabu -silent | ./fingerprintx target -f --json | jq
{
  "Target": "10.10.11.168:53",
  "Service": "udp/dns"
}
{
  "Target": "10.10.11.168:1433",
  "Service": "tcp/mssql",
  "Metadata": {
    "Version": "15.0.2000\n"
  }
}
{
  "Target": "10.10.11.168:80",
  "Service": "tcp/http",
  "Metadata": {
    "Response Headers": {
      "Accept-Ranges": [
        "bytes"
      ],
      "Content-Length": [
        "2313"
      ],
      "Content-Type": [
        "text/html"
      ],
      "Date": [
        "Wed, 10 Aug 2022 21:08:44 GMT"
      ],
      "Etag": [
        "\"3aed29a2a7d1d71:0\""
      ],
      "Last-Modified": [
        "Thu, 04 Nov 2021 18:13:14 GMT"
      ],
      "Server": [
        "Microsoft-IIS/10.0"
      ]
    },
    "Status": "200 OK",
    "Status Code": "200",
    "Version": "Microsoft-IIS/10.0"
  }
}
{
  "Target": "10.10.11.168:389",
  "Service": "tcp/ldap"
}
{
  "Target": "10.10.11.168:445",
  "Service": "tcp/smb",
  "Metadata": {
    "SigningEnabled": "true",
    "SigningRequired": "true"
  }
}
```