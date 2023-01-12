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
	"log"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

func UDPScan(targets []plugins.Target, config Config) ([]plugins.Service, error) {
	var results []plugins.Service
	for _, target := range targets {
		result, err := config.UDPScanTarget(target)
		if err == nil && result != nil {
			results = append(results, *result)
		}
		if config.Verbose && err != nil {
			log.Printf("%s\n", err)
		}
	}

	return results, nil
}

// ScanTargets fingerprints service(s) running given a list of targets.
func ScanTargets(targets []plugins.Target, config Config) ([]plugins.Service, error) {
	var results []plugins.Service

	if config.UDP {
		return UDPScan(targets, config)
	}

	for _, target := range targets {
		result, err := config.SimpleScanTarget(target)
		if err == nil && result != nil {
			results = append(results, *result)
		}
		if config.Verbose && err != nil {
			log.Printf("%s\n", err)
		}
	}

	return results, nil
}
