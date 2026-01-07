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
	"testing"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

// TestExtractVersionFromMetrics tests parsing version from Prometheus metrics
func TestExtractVersionFromMetrics(t *testing.T) {
	tests := []struct {
		name        string
		metrics     string
		wantVersion string
		description string
	}{
		{
			name:        "typical Milvus 2.x version",
			metrics:     `milvus_build_info{version="2.6.7",build_time="2024-01-15",git_commit="abc123"} 1`,
			wantVersion: "2.6.7",
			description: "Standard Prometheus metric with version label",
		},
		{
			name:        "version with v prefix",
			metrics:     `milvus_build_info{version="v2.6.7",build_time="2024-01-15"} 1`,
			wantVersion: "2.6.7",
			description: "Version with v prefix should be stripped",
		},
		{
			name:        "version first in labels",
			metrics:     `milvus_build_info{version="2.6.7",other="value"} 1`,
			wantVersion: "2.6.7",
			description: "Version as first label should be parsed",
		},
		{
			name:        "version last in labels",
			metrics:     `milvus_build_info{other="value",version="2.6.7"} 1`,
			wantVersion: "2.6.7",
			description: "Version as last label should be parsed",
		},
		{
			name:        "version middle in labels",
			metrics:     `milvus_build_info{before="value",version="2.6.7",after="value"} 1`,
			wantVersion: "2.6.7",
			description: "Version in middle of labels should be parsed",
		},
		{
			name:        "version with pre-release tag",
			metrics:     `milvus_build_info{version="2.6.7-beta.1"} 1`,
			wantVersion: "2.6.7-beta.1",
			description: "Version with pre-release tag should be preserved",
		},
		{
			name:        "version with rc tag",
			metrics:     `milvus_build_info{version="2.6.7-rc.2"} 1`,
			wantVersion: "2.6.7-rc.2",
			description: "Release candidate version should be preserved",
		},
		{
			name:        "Milvus 1.x version",
			metrics:     `milvus_build_info{version="1.1.1"} 1`,
			wantVersion: "1.1.1",
			description: "Older 1.x version should be parsed",
		},
		{
			name:        "no version label",
			metrics:     `milvus_build_info{build_time="2024-01-15"} 1`,
			wantVersion: "",
			description: "Metric without version label should return empty string",
		},
		{
			name:        "no milvus_build_info metric",
			metrics:     `other_metric{version="2.6.7"} 1`,
			wantVersion: "",
			description: "Non-Milvus metric should return empty string",
		},
		{
			name:        "empty metrics",
			metrics:     ``,
			wantVersion: "",
			description: "Empty metrics should return empty string",
		},
		{
			name: "metrics with multiple lines",
			metrics: `# HELP milvus_build_info Build information
# TYPE milvus_build_info gauge
milvus_build_info{version="2.6.7",build_time="2024-01-15"} 1
other_metric{label="value"} 42`,
			wantVersion: "2.6.7",
			description: "Version should be extracted from multi-line metrics",
		},
		{
			name: "version in middle of large metrics response",
			metrics: `metric1{label="value"} 1
metric2{label="value"} 2
milvus_build_info{version="2.6.7",build_time="2024-01-15"} 1
metric3{label="value"} 3`,
			wantVersion: "2.6.7",
			description: "Version should be found in large metrics output",
		},
		{
			name:        "version with uppercase V prefix",
			metrics:     `milvus_build_info{version="V2.6.7"} 1`,
			wantVersion: "V2.6.7",
			description: "Uppercase V prefix not handled (regex is case-sensitive)",
		},
		{
			name:        "version with leading whitespace in value",
			metrics:     `milvus_build_info{version="  2.6.7"} 1`,
			wantVersion: "  2.6.7",
			description: "Leading whitespace in version value preserved",
		},
		{
			name:        "version with trailing whitespace in value",
			metrics:     `milvus_build_info{version="2.6.7  "} 1`,
			wantVersion: "2.6.7  ",
			description: "Trailing whitespace in version value preserved",
		},
		{
			name:        "version with special characters",
			metrics:     `milvus_build_info{version="2.6.7+build.123"} 1`,
			wantVersion: "2.6.7+build.123",
			description: "Version with build metadata should be preserved",
		},
		{
			name:        "malformed label (missing closing quote)",
			metrics:     `milvus_build_info{version="2.6.7} 1`,
			wantVersion: "",
			description: "Malformed label should not match",
		},
		{
			name:        "malformed label (missing opening quote)",
			metrics:     `milvus_build_info{version=2.6.7"} 1`,
			wantVersion: "",
			description: "Malformed label should not match",
		},
		{
			name:        "version with complex pre-release",
			metrics:     `milvus_build_info{version="2.6.7-beta.1.2.3"} 1`,
			wantVersion: "2.6.7-beta.1.2.3",
			description: "Complex pre-release notation should be captured",
		},
		{
			name:        "multiple milvus_build_info entries (edge case)",
			metrics:     `milvus_build_info{version="1.0.0"} 1\nmilvus_build_info{version="2.6.7"} 1`,
			wantVersion: "1.0.0",
			description: "First match should be returned",
		},
		{
			name:        "version label with single quotes (non-standard)",
			metrics:     `milvus_build_info{version='2.6.7'} 1`,
			wantVersion: "",
			description: "Single quotes should not match (Prometheus uses double quotes)",
		},
		{
			name:        "version with dashes in pre-release",
			metrics:     `milvus_build_info{version="2.6.7-beta-fixes"} 1`,
			wantVersion: "2.6.7-beta-fixes",
			description: "Dashes in pre-release should be preserved",
		},
		{
			name:        "zero version",
			metrics:     `milvus_build_info{version="0.0.0"} 1`,
			wantVersion: "0.0.0",
			description: "Zero version should be valid",
		},
		{
			name:        "large version numbers",
			metrics:     `milvus_build_info{version="99.88.77"} 1`,
			wantVersion: "99.88.77",
			description: "Large version numbers should be parsed",
		},
		{
			name:        "version with build metadata",
			metrics:     `milvus_build_info{version="2.6.7+20240115.abc123"} 1`,
			wantVersion: "2.6.7+20240115.abc123",
			description: "Build metadata should be preserved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractVersionFromMetrics(tt.metrics)

			if result != tt.wantVersion {
				t.Errorf("extractVersionFromMetrics() = %q, want %q\nDescription: %s",
					result, tt.wantVersion, tt.description)
			}
		})
	}
}

// TestMilvusMetricsPluginInterface tests the plugin interface methods
func TestMilvusMetricsPluginInterface(t *testing.T) {
	plugin := &MilvusMetricsPlugin{}

	t.Run("Name", func(t *testing.T) {
		if name := plugin.Name(); name != MILVUS_METRICS {
			t.Errorf("Name() = %q, want %q", name, MILVUS_METRICS)
		}
	})

	t.Run("Type", func(t *testing.T) {
		if pluginType := plugin.Type(); pluginType != plugins.TCP {
			t.Errorf("Type() = %v, want TCP (%v)", pluginType, plugins.TCP)
		}
	})

	t.Run("Priority", func(t *testing.T) {
		priority := plugin.Priority()
		if priority != 51 {
			t.Errorf("Priority() = %d, want 51", priority)
		}
		if priority <= 50 {
			t.Error("Priority should be > 50 to run after main Milvus plugin")
		}
	})

	t.Run("PortPriority default port 9091", func(t *testing.T) {
		if !plugin.PortPriority(9091) {
			t.Error("PortPriority(9091) = false, want true")
		}
	})

	t.Run("PortPriority non-default port 19530 (main service)", func(t *testing.T) {
		if plugin.PortPriority(19530) {
			t.Error("PortPriority(19530) = true, want false (main service port not priority for metrics)")
		}
	})

	t.Run("PortPriority non-default port 8080", func(t *testing.T) {
		if plugin.PortPriority(8080) {
			t.Error("PortPriority(8080) = true, want false")
		}
	})

	t.Run("PortPriority port 0", func(t *testing.T) {
		if plugin.PortPriority(0) {
			t.Error("PortPriority(0) = true, want false")
		}
	})

	t.Run("PortPriority port 65535", func(t *testing.T) {
		if plugin.PortPriority(65535) {
			t.Error("PortPriority(65535) = true, want false")
		}
	})
}

// TestBuildMilvusCPEReusability tests that buildMilvusCPE is reusable between plugins
func TestBuildMilvusCPEReusability(t *testing.T) {
	// This test verifies that both main plugin and metrics plugin use the same CPE format
	tests := []struct {
		name        string
		version     string
		wantCPE     string
		description string
	}{
		{
			name:        "Milvus 2.6.7 from metrics",
			version:     "2.6.7",
			wantCPE:     "cpe:2.3:a:milvus:milvus:2.6.7:*:*:*:*:*:*:*",
			description: "Metrics plugin should generate same CPE as main plugin",
		},
		{
			name:        "unknown version from metrics (wildcard)",
			version:     "",
			wantCPE:     "cpe:2.3:a:milvus:milvus:*:*:*:*:*:*:*:*",
			description: "Metrics plugin should use wildcard for unknown version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildMilvusCPE(tt.version)

			if result != tt.wantCPE {
				t.Errorf("buildMilvusCPE(%q) = %q, want %q\nDescription: %s",
					tt.version, result, tt.wantCPE, tt.description)
			}
		})
	}
}
