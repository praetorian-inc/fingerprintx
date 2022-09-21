package scan

import (
	"log"
	"net/netip"
)

func UDPScan(targets []netip.AddrPort, config Config) ([]ReportedResult, error) {
	var results []ReportedResult
	for _, target := range targets {
		result, err := config.UDPScanTarget(target)
		if err == nil && result.Results != nil {
			results = append(results, result)
		}
		if config.Verbose && err != nil {
			log.Printf("%s\n", err)
		}
	}

	return results, nil
}

// ScanTargets fingerprints service(s) running given a list of targets.
func ScanTargets(targets []netip.AddrPort, config Config) ([]ReportedResult, error) {
	var results []ReportedResult
	identifiedServices := make(map[netip.AddrPort]bool)

	if config.UDP {
		return UDPScan(targets, config)
	}

	for _, target := range targets {
		result, err := config.simpleScanTarget(target, true)
		// TODO check check check
		if err == nil && result.Results != nil {
			// fmt.Printf("identified service: %v\n", result)
			results = append(results, result)
			identifiedServices[target] = true
		}
		if config.Verbose && err != nil {
			log.Printf("%s\n", err)
		}
	}

	// done with fastlane mode, return
	if config.FastlaneMode {
		return results, nil
	}

	// slow lane scanning
	for _, target := range targets {
		if !identifiedServices[target] {
			result, err := config.simpleScanTarget(target, false)
			if err == nil && result.Results != nil {
				results = append(results, result)
			}
			if config.Verbose && err != nil {
				log.Printf("%s\n", err)
			}
		}
	}

	return results, nil
}
