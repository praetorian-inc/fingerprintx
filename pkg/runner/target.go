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
)

var inputFile string

func readTargets(inputFile string) ([]netip.AddrPort, error) {
	targetsList := make([]netip.AddrPort, 0)
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
			} else {
				fmt.Printf("errored")
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
		}
	}
	return targetsList, nil
}

func parseTarget(inputTarget string) (netip.AddrPort, error) {
	target := strings.Split(strings.TrimSpace(inputTarget), ":")
	if len(target) != 2 {
		return netip.AddrPort{}, fmt.Errorf("invalid")
	}

	hostStr, portStr := target[0], target[1]

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid")
	}

	ip := net.ParseIP(hostStr)
	var isHostname = false
	if ip == nil {
		addrs, err := net.LookupIP(hostStr)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("invalid")
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
		return netip.AddrPort{}, fmt.Errorf("invalid")
	}
	targetAddr := netip.AddrPortFrom(addr, uint16(port))

	if isHostname {
		hostMapping[targetAddr] = hostStr
	}

	return targetAddr, nil
}
