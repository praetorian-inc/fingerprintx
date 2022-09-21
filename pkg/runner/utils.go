package runner

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/scan"
)

func checkConfig(config cliConfig) error {
	if len(config.outputFile) > 0 {
		_, err := os.Stat(config.outputFile)
		if !os.IsNotExist(err) && config.overwriteOutput {
			fmt.Printf("File: %s already exists. Overwrite? [Y/N] ", config.outputFile)
			fmt.Scan(&userInput)
			if strings.ToLower(userInput)[0] != 'y' {
				return fmt.Errorf("Output file %s already exists", config.outputFile)
			}
		}
	}
	if config.outputJSON && config.outputCSV {
		return errors.New("Only one output format can be specified (JSON or CSV)")
	}

	if config.useUDP && config.verbose {
		user, err := user.Current()
		if err != nil {
			return fmt.Errorf("Failed to retrieve current user (error: %w)", err)
		}
		if !((runtime.GOOS == "linux" || runtime.GOOS == "darwin") && user.Uid == "0") {
			fmt.Fprintln(os.Stderr, "Note: UDP Scan may require root privileges")
		}
	}

	if config.showErrors && !(config.outputJSON || config.outputCSV) {
		return errors.New("showErrors requires results being output in JSON or CSV format")
	}

	return nil
}

func createScanConfig(config cliConfig) scan.Config {
	var runMode = scan.Default
	if config.fastMode {
		runMode = scan.Fast
	}

	var protocol = plugins.TCP
	if config.useUDP {
		protocol = plugins.UDP
	}

	return scan.Config{
		Speed:                    runMode,
		DefaultTimeout:           time.Duration(config.timeout) * time.Millisecond,
		TargetProtocol:           protocol,
		FastlaneMode:             config.fastMode,
		MaxConcurrentConnections: config.maxConcurrentConnections,
		PacketsPerSecond:         config.packetsPerSecond,
		BitsPerSecond:            config.bitsPerSecond,
		ReportPluginErrors:       config.showErrors,
		UDP:                      config.useUDP,
		Verbose:                  config.verbose,
	}
}

func isPriorityPort(port int) bool {
	protocols := []plugins.Protocol{plugins.UDP, plugins.TCP, plugins.TCPTLS}
	for _, protocol := range protocols {
		if pluginList, exists := plugins.Plugins[protocol]; exists {
			for _, plugin := range pluginList {
				if plugin.PortPriority(uint16(port)) {
					return true
				}
			}
		}
	}
	return false
}

func DefaultPortRange() string {
	priorityPorts := make([]string, 0)
	var port int
	for port = 1; port <= 65535; port++ {
		if isPriorityPort(port) {
			priorityPorts = append(priorityPorts, strconv.Itoa(port))
		}
	}
	return strings.Join(priorityPorts, ",")
}
