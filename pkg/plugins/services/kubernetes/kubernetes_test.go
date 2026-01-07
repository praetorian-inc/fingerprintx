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
	"testing"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

// TestKubernetesPlugin_PortPriority tests that the plugin prioritizes correct ports
func TestKubernetesPlugin_PortPriority(t *testing.T) {
	plugin := &KubernetesPlugin{}

	tests := []struct {
		name     string
		port     uint16
		expected bool
	}{
		{"primary port 6443", 6443, true},
		{"production port 443", 443, false}, // 443 is generic HTTPS, not prioritized
		{"legacy port 8080", 8080, false},   // HTTP not TLS, different plugin
		{"random port", 9999, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.PortPriority(tt.port)
			if result != tt.expected {
				t.Errorf("PortPriority(%d) = %v, expected %v", tt.port, result, tt.expected)
			}
		})
	}
}

// TestKubernetesPlugin_Name tests the plugin name
func TestKubernetesPlugin_Name(t *testing.T) {
	plugin := &KubernetesPlugin{}
	if plugin.Name() != "kubernetes" {
		t.Errorf("Name() = %s, expected kubernetes", plugin.Name())
	}
}

// TestKubernetesPlugin_Type tests the protocol type
func TestKubernetesPlugin_Type(t *testing.T) {
	plugin := &KubernetesPlugin{}
	if plugin.Type() != plugins.TCPTLS {
		t.Errorf("Type() = %v, expected TCPTLS", plugin.Type())
	}
}

// TestKubernetesPlugin_Priority tests the execution priority
func TestKubernetesPlugin_Priority(t *testing.T) {
	plugin := &KubernetesPlugin{}
	priority := plugin.Priority()
	// Should run before generic HTTP (priority > 100)
	// Suggested priority: 30 based on research
	if priority >= 100 {
		t.Errorf("Priority() = %d, expected < 100 to run before generic HTTP", priority)
	}
}

// TestCheckKubernetesVersion tests version JSON validation
func TestCheckKubernetesVersion(t *testing.T) {
	tests := []struct {
		name        string
		jsonData    string
		expectValid bool
		expectError bool
	}{
		{
			name: "valid kubernetes version response",
			jsonData: `{
				"major": "1",
				"minor": "28",
				"gitVersion": "v1.28.3",
				"gitCommit": "a8a1abc1230946ecd179f17e528a40caec88f3e4",
				"gitTreeState": "clean",
				"buildDate": "2023-10-18T11:33:31Z",
				"goVersion": "go1.20.10",
				"compiler": "gc",
				"platform": "linux/amd64"
			}`,
			expectValid: true,
			expectError: false,
		},
		{
			name: "valid K3s version",
			jsonData: `{
				"major": "1",
				"minor": "28",
				"gitVersion": "v1.28.3+k3s1",
				"gitCommit": "abc123",
				"gitTreeState": "clean",
				"buildDate": "2023-10-18T11:33:31Z",
				"goVersion": "go1.20.10",
				"compiler": "gc",
				"platform": "linux/amd64"
			}`,
			expectValid: true,
			expectError: false,
		},
		{
			name: "valid GKE version",
			jsonData: `{
				"major": "1",
				"minor": "28",
				"gitVersion": "v1.28.3+gke.1",
				"gitCommit": "abc123",
				"gitTreeState": "clean",
				"buildDate": "2023-10-18T11:33:31Z",
				"goVersion": "go1.20.10",
				"compiler": "gc",
				"platform": "linux/amd64"
			}`,
			expectValid: true,
			expectError: false,
		},
		{
			name:        "missing major field",
			jsonData:    `{"minor": "28", "gitVersion": "v1.28.3"}`,
			expectValid: false,
			expectError: true,
		},
		{
			name:        "missing minor field",
			jsonData:    `{"major": "1", "gitVersion": "v1.28.3"}`,
			expectValid: false,
			expectError: true,
		},
		{
			name:        "missing gitVersion field",
			jsonData:    `{"major": "1", "minor": "28"}`,
			expectValid: false,
			expectError: true,
		},
		{
			name:        "invalid gitVersion format (no v prefix)",
			jsonData:    `{"major": "1", "minor": "28", "gitVersion": "1.28.3"}`,
			expectValid: false,
			expectError: true,
		},
		{
			name:        "invalid gitVersion format (not semantic version)",
			jsonData:    `{"major": "1", "minor": "28", "gitVersion": "invalid"}`,
			expectValid: false,
			expectError: true,
		},
		{
			name:        "empty JSON",
			jsonData:    `{}`,
			expectValid: false,
			expectError: true,
		},
		{
			name:        "not JSON",
			jsonData:    `not json`,
			expectValid: false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := checkKubernetesVersion([]byte(tt.jsonData))

			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectValid && result.GitVersion == "" {
				t.Errorf("expected valid version but got empty")
			}
		})
	}
}

// TestExtractKubernetesVersion tests version extraction from gitVersion field
func TestExtractKubernetesVersion(t *testing.T) {
	tests := []struct {
		name        string
		gitVersion  string
		expectMajor string
		expectMinor string
		expectPatch string
	}{
		{"standard version", "v1.28.3", "1", "28", "3"},
		{"pre-release version", "v1.29.0-alpha.1", "1", "29", "0"},
		{"K3s version", "v1.28.3+k3s1", "1", "28", "3"},
		{"GKE version", "v1.28.3+gke.1", "1", "28", "3"},
		{"EKS version", "v1.28.3+eks.1", "1", "28", "3"},
		{"AKS version", "v1.28.3+aks.1", "1", "28", "3"},
		{"OpenShift version", "v1.25.0+openshift", "1", "25", "0"},
		{"empty version", "", "", "", ""},
		{"version with only major.minor", "v1.28", "1", "28", "0"},
		{"version with only major", "v1", "1", "0", "0"},
		{"version without parts after split", "v", "", "0", "0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			major, minor, patch := extractKubernetesVersion(tt.gitVersion)
			if major != tt.expectMajor || minor != tt.expectMinor || patch != tt.expectPatch {
				t.Errorf("extractKubernetesVersion(%s) = %s.%s.%s, expected %s.%s.%s",
					tt.gitVersion, major, minor, patch,
					tt.expectMajor, tt.expectMinor, tt.expectPatch)
			}
		})
	}
}

// TestDetectDistribution tests Kubernetes distribution detection
func TestDetectDistribution(t *testing.T) {
	tests := []struct {
		name           string
		gitVersion     string
		expectedDist   string
		expectedVendor string
	}{
		{"K3s", "v1.28.3+k3s1", "k3s", "rancher"},
		{"RKE2", "v1.28.3+rke2r1", "rke2", "rancher"},
		{"GKE", "v1.28.3+gke.1", "gke", "google"},
		{"EKS", "v1.28.3+eks.1", "eks", "aws"},
		{"AKS", "v1.28.3+aks.1", "aks", "azure"},
		{"OpenShift", "v1.25.0+openshift", "openshift", "redhat"},
		{"Minikube", "v1.28.3.minikube.0", "minikube", "kubernetes"},
		{"Vanilla", "v1.28.3", "vanilla", "kubernetes"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dist, vendor := detectDistribution(tt.gitVersion)
			if dist != tt.expectedDist {
				t.Errorf("detectDistribution(%s) distribution = %s, expected %s",
					tt.gitVersion, dist, tt.expectedDist)
			}
			if vendor != tt.expectedVendor {
				t.Errorf("detectDistribution(%s) vendor = %s, expected %s",
					tt.gitVersion, vendor, tt.expectedVendor)
			}
		})
	}
}

// TestBuildKubernetesCPE tests CPE generation
func TestBuildKubernetesCPE(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		vendor      string
		expectedCPE string
	}{
		{
			"vanilla kubernetes",
			"1.28.3",
			"kubernetes",
			"cpe:2.3:a:kubernetes:kubernetes:1.28.3:*:*:*:*:*:*:*",
		},
		{
			"openshift",
			"4.14.0",
			"redhat",
			"cpe:2.3:a:redhat:openshift:4.14.0:*:*:*:*:*:*:*",
		},
		{
			"empty version",
			"",
			"kubernetes",
			"cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildKubernetesCPE(tt.version, tt.vendor)
			if cpe != tt.expectedCPE {
				t.Errorf("buildKubernetesCPE(%s, %s) = %s, expected %s",
					tt.version, tt.vendor, cpe, tt.expectedCPE)
			}
		})
	}
}

