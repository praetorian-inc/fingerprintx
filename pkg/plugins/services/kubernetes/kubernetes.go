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

package kubernetes

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type KubernetesPlugin struct{}

const KUBERNETES = "kubernetes"

// VersionInfo represents the structure of Kubernetes /version endpoint response
type VersionInfo struct {
	Major         string `json:"major"`
	Minor         string `json:"minor"`
	GitVersion    string `json:"gitVersion"`
	GitCommit     string `json:"gitCommit"`
	GitTreeState  string `json:"gitTreeState"`
	BuildDate     string `json:"buildDate"`
	GoVersion     string `json:"goVersion"`
	Compiler      string `json:"compiler"`
	Platform      string `json:"platform"`
}

func init() {
	plugins.RegisterPlugin(&KubernetesPlugin{})
}

func (p *KubernetesPlugin) PortPriority(port uint16) bool {
	// Prioritize port 6443 (default Kubernetes API server port)
	return port == 6443
}

func (p *KubernetesPlugin) Name() string {
	return KUBERNETES
}

func (p *KubernetesPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *KubernetesPlugin) Priority() int {
	// Priority 30 - run before generic HTTP (100+) but after very specific protocols
	return 30
}

func (p *KubernetesPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Create HTTP client that uses the provided connection and skips TLS verification
	// (Kubernetes clusters often use self-signed certificates)
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
	}

	// Phase 1: Detection - Query /version endpoint
	// The /version endpoint is accessible without authentication by default
	// via the system:public-info-viewer clusterrole
	versionURL := fmt.Sprintf("https://%s/version", conn.RemoteAddr().String())
	req, err := http.NewRequest("GET", versionURL, nil)
	if err != nil {
		return nil, err
	}

	// Set headers to mimic kubectl client
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "fingerprintx/1.0")

	// If host is provided in target, use it for SNI
	if target.Host != "" {
		req.Host = target.Host
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil
	}

	// Validate the response is from Kubernetes
	versionInfo, err := checkKubernetesVersion(body)
	if err != nil {
		return nil, nil
	}

	// Phase 2: Enrichment - Extract version and distribution metadata
	major, minor, patch := extractKubernetesVersion(versionInfo.GitVersion)
	version := fmt.Sprintf("%s.%s.%s", major, minor, patch)

	// Detect distribution (K3s, GKE, EKS, OpenShift, etc.)
	distribution, vendor := detectDistribution(versionInfo.GitVersion)

	// Generate CPE
	cpe := buildKubernetesCPE(version, vendor)

	// Build metadata payload
	payload := plugins.ServiceKubernetes{
		CPEs:         []string{cpe},
		GitVersion:   versionInfo.GitVersion,
		GitCommit:    versionInfo.GitCommit,
		BuildDate:    versionInfo.BuildDate,
		GoVersion:    versionInfo.GoVersion,
		Platform:     versionInfo.Platform,
		Distribution: distribution,
		Vendor:       vendor,
	}

	return plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS), nil
}

// checkKubernetesVersion validates that the response is from a Kubernetes API server
// by checking the required fields and gitVersion format
func checkKubernetesVersion(data []byte) (VersionInfo, error) {
	var versionInfo VersionInfo

	// Try to parse as JSON
	err := json.Unmarshal(data, &versionInfo)
	if err != nil {
		return VersionInfo{}, &utils.InvalidResponseErrorInfo{
			Service: KUBERNETES,
			Info:    "invalid JSON response",
		}
	}

	// Validate required fields are present
	if versionInfo.Major == "" {
		return VersionInfo{}, &utils.InvalidResponseErrorInfo{
			Service: KUBERNETES,
			Info:    "missing major field",
		}
	}
	if versionInfo.Minor == "" {
		return VersionInfo{}, &utils.InvalidResponseErrorInfo{
			Service: KUBERNETES,
			Info:    "missing minor field",
		}
	}
	if versionInfo.GitVersion == "" {
		return VersionInfo{}, &utils.InvalidResponseErrorInfo{
			Service: KUBERNETES,
			Info:    "missing gitVersion field",
		}
	}

	// Validate gitVersion format: v{major}.{minor}.{patch}[+suffix|-suffix]
	// Examples: v1.28.3, v1.29.0-alpha.1, v1.28.3+k3s1
	gitVersionRegex := regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+`)
	if !gitVersionRegex.MatchString(versionInfo.GitVersion) {
		return VersionInfo{}, &utils.InvalidResponseErrorInfo{
			Service: KUBERNETES,
			Info:    "invalid gitVersion format",
		}
	}

	return versionInfo, nil
}

// extractKubernetesVersion extracts major, minor, patch from gitVersion field
// Examples:
//   - v1.28.3 -> 1, 28, 3
//   - v1.29.0-alpha.1 -> 1, 29, 0
//   - v1.28.3+k3s1 -> 1, 28, 3
func extractKubernetesVersion(gitVersion string) (major, minor, patch string) {
	if gitVersion == "" {
		return "", "", ""
	}

	// Remove 'v' prefix
	version := strings.TrimPrefix(gitVersion, "v")

	// Split by '-' or '+' to remove suffixes (pre-release, build metadata)
	version = strings.Split(version, "-")[0]
	version = strings.Split(version, "+")[0]

	// Split by '.' to get major.minor.patch
	parts := strings.Split(version, ".")
	if len(parts) >= 3 {
		return parts[0], parts[1], parts[2]
	}
	if len(parts) == 2 {
		return parts[0], parts[1], "0"
	}
	if len(parts) == 1 {
		return parts[0], "0", "0"
	}

	return "", "", ""
}

// detectDistribution identifies Kubernetes distribution and vendor from gitVersion suffix
func detectDistribution(gitVersion string) (distribution, vendor string) {
	gitLower := strings.ToLower(gitVersion)

	// Check for distribution suffixes
	if strings.Contains(gitLower, "+k3s") {
		return "k3s", "rancher"
	}
	if strings.Contains(gitLower, "+rke2") {
		return "rke2", "rancher"
	}
	if strings.Contains(gitLower, "+gke") {
		return "gke", "google"
	}
	if strings.Contains(gitLower, "+eks") {
		return "eks", "aws"
	}
	if strings.Contains(gitLower, "+aks") {
		return "aks", "azure"
	}
	if strings.Contains(gitLower, "openshift") {
		return "openshift", "redhat"
	}
	if strings.Contains(gitLower, ".minikube") {
		return "minikube", "kubernetes"
	}

	// Default to vanilla Kubernetes
	return "vanilla", "kubernetes"
}

// buildKubernetesCPE generates a CPE (Common Platform Enumeration) string for Kubernetes
// CPE format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
func buildKubernetesCPE(version, vendor string) string {
	// Use wildcard for unknown versions
	if version == "" {
		version = "*"
	}

	product := "kubernetes"
	if vendor == "redhat" {
		product = "openshift"
	}

	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
}
