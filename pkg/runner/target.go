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

package runner

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

var inputFile string

func readTargets(inputFile string, verbose bool) ([]plugins.Target, error) {
	targetsList := make([]plugins.Target, 0)
	var readFile *os.File
	if len(inputFile) == 0 && len(targetList) == 0 {
		fi, _ := os.Stdin.Stat()
		if (fi.Mode() & os.ModeCharDevice) != 0 { // if no piped input
			return targetsList, errors.New("missing input of targets")
		}
		readFile = os.Stdin
	} else if len(targetList) > 0 {
		for _, target := range targetList {
			parsedTarget, err := parseTarget(target)
			if err == nil {
				targetsList = append(targetsList, parsedTarget)
			} else if verbose {
				fmt.Printf("%s\n", err)
			}
		}
	} else {
		file, err := os.Open(inputFile)
		if err != nil {
			return targetsList, err
		}
		readFile = file
	}
	defer readFile.Close()

	scanner := bufio.NewScanner(readFile)
	for scanner.Scan() {
		parsedTarget, err := parseTarget(scanner.Text())
		if err == nil {
			targetsList = append(targetsList, parsedTarget)
		} else if verbose {
			fmt.Printf("%s\n", err)
		}
	}
	return targetsList, nil
}

func parseTarget(inputTarget string) (plugins.Target, error) {
	scanTarget := plugins.Target{}
	target := strings.Split(strings.TrimSpace(inputTarget), ":")
	if len(target) != 2 {
		return plugins.Target{}, fmt.Errorf("invalid target: %s", inputTarget)
	}

	hostStr, portStr := target[0], target[1]

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return plugins.Target{}, fmt.Errorf("invalid port specified")
	}

	ip := net.ParseIP(hostStr)
	var isHostname = false
	if ip == nil {
		var addrs []net.IP
		addrs, err = net.LookupIP(hostStr)
		if err != nil {
			return plugins.Target{}, err
		}
		isHostname = true
		ip = addrs[0]
	}

	// use IPv4 representation if possible
	ipv4 := ip.To4()
	if ipv4 != nil {
		ip = ipv4
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return plugins.Target{}, fmt.Errorf("invalid ip address specified %s", err)
	}
	targetAddr := netip.AddrPortFrom(addr, uint16(port))
	scanTarget.Address = targetAddr

	if isHostname {
		scanTarget.Host = hostStr
	}

	return scanTarget, nil
}
