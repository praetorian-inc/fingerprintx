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

package milvus

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

/*
Milvus Prometheus Metrics Fingerprinting

This plugin detects Milvus via its Prometheus metrics endpoint on port 9091.
This is separate from the main Milvus plugin (port 19530) to follow the
fingerprintx principle: one plugin per port/protocol combination.

Detection Strategy:
  PHASE 1 - DETECTION:
    - GET http://host:9091/metrics
    - Look for "milvus_build_info" metric in Prometheus exposition format
    - If found → Milvus metrics detected

  PHASE 2 - ENRICHMENT:
    - Extract version from milvus_build_info{version="v2.6.7",...} label
    - Version extraction may fail if label format changes

Protocol Details:
  Endpoint: GET /metrics (port 9091)
  Format: Prometheus exposition format (text-based)
  Key metric: milvus_build_info{version="v2.6.7",build_time="...",git_commit="..."} 1

Default Port:
  - 9091: Prometheus metrics endpoint

Version Compatibility:
  - Milvus 2.x: Exposes milvus_build_info metric
  - Milvus 1.x: May not have metrics endpoint or different format

CPE Format:
  - cpe:2.3:a:milvus:milvus:{version}:*:*:*:*:*:*:*
  - Uses "*" for unknown version if metric found but version extraction fails

NOTE: For main database service (port 19530), see milvus.go
*/

type MilvusMetricsPlugin struct{}

const MILVUS_METRICS = "milvus-metrics"

func init() {
	plugins.RegisterPlugin(&MilvusMetricsPlugin{})
}

// DetectMilvusMetrics performs Milvus detection via Prometheus metrics endpoint.
//
// Parameters:
//   - conn: Existing network connection to reuse
//   - target: Target information (host for Host header)
//   - timeout: HTTP request timeout duration
//
// Returns:
//   - string: Version string if successful, empty string otherwise
//   - bool: true if Milvus metrics detected
//   - error: Error details if detection failed
func DetectMilvusMetrics(conn net.Conn, target plugins.Target, timeout time.Duration) (string, bool, error) {
	// Build metrics URL using remote address from connection (gives "IP:port")
	metricsURL := fmt.Sprintf("http://%s/metrics", conn.RemoteAddr().String())

	// Create HTTP request manually to specify path
	req, err := http.NewRequest("GET", metricsURL, nil)
	if err != nil {
		return "", false, err
	}

	// Set Host header if target specifies one
	if target.Host != "" {
		req.Host = target.Host
	}

	// Create HTTP client with custom dialer to reuse the provided connection
	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("metrics endpoint returned status %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, err
	}

	bodyStr := string(body)

	// Look for milvus_build_info metric
	// Format: milvus_build_info{version="v2.6.7",build_time="...",git_commit="..."} 1
	if !strings.Contains(bodyStr, "milvus_build_info") {
		return "", false, nil // Not Milvus metrics
	}

	// Milvus metrics detected - extract version from label
	version := extractVersionFromMetrics(bodyStr)

	return version, true, nil
}

// extractVersionFromMetrics extracts version from Prometheus metrics response.
//
// Looks for milvus_build_info metric and parses the version label.
//
// Parameters:
//   - metrics: Prometheus metrics response body
//
// Returns:
//   - string: Extracted version string, or empty if not found
func extractVersionFromMetrics(metrics string) string {
	// Extract version from milvus_build_info label
	// Pattern: milvus_build_info{version="v2.6.7",...} or milvus_build_info{...,version="v2.6.7",...}
	versionRegex := regexp.MustCompile(`milvus_build_info\{[^}]*version="v?([^"]+)"`)
	matches := versionRegex.FindStringSubmatch(metrics)
	if len(matches) >= 2 {
		version := matches[1]
		return strings.TrimPrefix(version, "v")
	}

	return ""
}

func (p *MilvusMetricsPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	version, detected, err := DetectMilvusMetrics(conn, target, timeout)
	if !detected {
		return nil, err
	}

	// Milvus metrics detected - create service payload
	payload := plugins.ServiceMilvusMetrics{}

	// Always generate CPE - uses "*" for unknown version
	cpe := buildMilvusCPE(version)
	payload.CPEs = []string{cpe}

	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *MilvusMetricsPlugin) PortPriority(port uint16) bool {
	return port == 9091
}

func (p *MilvusMetricsPlugin) Name() string {
	return MILVUS_METRICS
}

func (p *MilvusMetricsPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *MilvusMetricsPlugin) Priority() int {
	return 51 // Run after main Milvus plugin (50)
}
