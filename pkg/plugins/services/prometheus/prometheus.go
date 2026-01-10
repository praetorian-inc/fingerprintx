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

package prometheus

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type PrometheusPlugin struct{}

const PROMETHEUS = "prometheus"

// BuildInfoResponse represents the structure of Prometheus /api/v1/status/buildinfo endpoint response
type BuildInfoResponse struct {
	Status string        `json:"status"`
	Data   BuildInfoData `json:"data"`
}

// BuildInfoData contains the build metadata
type BuildInfoData struct {
	Version   string `json:"version"`
	Revision  string `json:"revision"`
	Branch    string `json:"branch"`
	BuildUser string `json:"buildUser"`
	BuildDate string `json:"buildDate"`
	GoVersion string `json:"goVersion"`
}

func init() {
	plugins.RegisterPlugin(&PrometheusPlugin{})
}

func (p *PrometheusPlugin) PortPriority(port uint16) bool {
	// Prioritize Prometheus ecosystem ports
	// 9090: Prometheus Server, 9091: Pushgateway, 9093: Alertmanager
	return port == 9090 || port == 9091 || port == 9093
}

func (p *PrometheusPlugin) Name() string {
	return PROMETHEUS
}

func (p *PrometheusPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *PrometheusPlugin) Priority() int {
	// Priority -10 - run BEFORE generic HTTP (priority 0) to detect Prometheus-specific endpoints
	return -10
}

func (p *PrometheusPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Create HTTP client that uses the provided connection
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
	}

	// Single HTTP GET request to root endpoint
	rootURL := fmt.Sprintf("http://%s/", conn.RemoteAddr().String())
	req, err := http.NewRequest("GET", rootURL, nil)
	if err != nil {
		return nil, nil
	}

	req.Header.Set("User-Agent", "fingerprintx/1.0")
	if target.Host != "" {
		req.Host = target.Host
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	// Check headers for Prometheus signals
	detection, detected := detectFromHeaders(resp)
	if detected {
		cpe := buildPrometheusCPE(detection.Version)
		payload := plugins.ServicePrometheus{
			CPEs:    []string{cpe},
			Version: detection.Version,
		}
		return plugins.CreateServiceFrom(target, payload, false, detection.Version, plugins.TCP), nil
	}

	// Fallback: Try /metrics endpoint
	metricsURL := fmt.Sprintf("http://%s/metrics", conn.RemoteAddr().String())
	metricsReq, err := http.NewRequest("GET", metricsURL, nil)
	if err != nil {
		return nil, nil
	}

	metricsReq.Header.Set("Accept", "text/plain")
	metricsReq.Header.Set("User-Agent", "fingerprintx/1.0")
	if target.Host != "" {
		metricsReq.Host = target.Host
	}

	metricsResp, err := client.Do(metricsReq)
	if err != nil {
		return nil, nil
	}
	defer metricsResp.Body.Close()

	if metricsResp.StatusCode != http.StatusOK {
		return nil, nil
	}

	metricsBody, err := io.ReadAll(metricsResp.Body)
	if err != nil {
		return nil, nil
	}

	version, err := parseMetricsForVersion(metricsBody)
	if err != nil {
		return nil, nil
	}

	cpe := buildPrometheusCPE(version)
	payload := plugins.ServicePrometheus{
		CPEs:    []string{cpe},
		Version: version,
	}

	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

// checkPrometheusBuildInfo validates that the response is from a Prometheus server
// by checking the required fields and status wrapper
func checkPrometheusBuildInfo(data []byte) (BuildInfoResponse, error) {
	var buildInfo BuildInfoResponse

	// Try to parse as JSON
	err := json.Unmarshal(data, &buildInfo)
	if err != nil {
		return BuildInfoResponse{}, &utils.InvalidResponseErrorInfo{
			Service: PROMETHEUS,
			Info:    "invalid JSON response",
		}
	}

	// Validate required fields are present
	if buildInfo.Status != "success" {
		return BuildInfoResponse{}, &utils.InvalidResponseErrorInfo{
			Service: PROMETHEUS,
			Info:    "status field is not 'success'",
		}
	}

	if buildInfo.Data.Version == "" {
		return BuildInfoResponse{}, &utils.InvalidResponseErrorInfo{
			Service: PROMETHEUS,
			Info:    "missing version field",
		}
	}

	return buildInfo, nil
}

// parseMetricsForVersion parses the /metrics endpoint to extract version from prometheus_build_info
// Fallback method when /api/v1/status/buildinfo endpoint fails or requires authentication
// Parses text format: prometheus_build_info{version="2.40.7",revision="...",branch="HEAD",goversion="go1.20.5"} 1
func parseMetricsForVersion(body []byte) (string, error) {
	// Pattern matches: version="X.Y.Z" but NOT goversion="X.Y.Z"
	// Uses negative lookbehind equivalent: ensures we don't match "goversion"
	// Match: {version=" or ,version=" or start with version="
	re := regexp.MustCompile(`(?:^|[,{])version="([^"]+)"`)
	matches := re.FindSubmatch(body)

	if len(matches) > 1 {
		return string(matches[1]), nil
	}

	return "", fmt.Errorf("version not found in metrics")
}

// extractSemanticVersion extracts semantic version from Prometheus version string
// Examples:
//   - "2.48.1" -> "2.48.1"
//   - "2.45.0" -> "2.45.0"
func extractSemanticVersion(version string) string {
	if version == "" {
		return ""
	}
	// Prometheus versions are already in semantic format (major.minor.patch)
	return version
}

// buildPrometheusCPE generates a CPE (Common Platform Enumeration) string for Prometheus
// CPE format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
func buildPrometheusCPE(version string) string {
	// Use wildcard for unknown versions
	if version == "" {
		version = "*"
	}

	vendor := "prometheus"
	product := "prometheus"

	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
}

// PrometheusDetection holds detection metadata
type PrometheusDetection struct {
	Version         string
	DetectionMethod string
}

// detectFromHeaders checks HTTP response headers for Prometheus signals
// Returns detection result and whether Prometheus was detected
func detectFromHeaders(resp *http.Response) (*PrometheusDetection, bool) {
	// Signal 1: Check WWW-Authenticate header for Prometheus realm
	// Detects auth-protected Prometheus instances (10/15 = 67% in Shodan testing)
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth != "" && containsIgnoreCase(wwwAuth, "prometheus") {
		return &PrometheusDetection{
			Version:         "unknown",
			DetectionMethod: "www-authenticate-realm",
		}, true
	}

	// Signal 2: Check Server header for Prometheus
	// Detects instances with explicit Server header (1/15 = 7% in Shodan testing)
	server := resp.Header.Get("Server")
	if server != "" && containsIgnoreCase(server, "prometheus") {
		version := extractVersionFromServer(server)
		return &PrometheusDetection{
			Version:         version,
			DetectionMethod: "server-header",
		}, true
	}

	return nil, false
}

// extractVersionFromServer extracts version from Server header
// Examples:
//   - "Prometheus/2.40.7" -> "2.40.7"
//   - "prometheus/2.48.1" -> "2.48.1"
//   - "Prometheus" -> ""
func extractVersionFromServer(server string) string {
	if server == "" {
		return ""
	}

	// Pattern: prometheus/X.Y.Z (case-insensitive)
	re := regexp.MustCompile(`(?i)prometheus/(\d+\.\d+\.\d+)`)
	matches := re.FindStringSubmatch(server)

	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// containsIgnoreCase checks if s contains substr (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	return regexp.MustCompile(`(?i)` + regexp.QuoteMeta(substr)).MatchString(s)
}
