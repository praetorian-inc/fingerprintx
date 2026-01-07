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

// TestParseVersionFromProtobuf tests parsing version strings from protobuf responses
func TestParseVersionFromProtobuf(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantVersion string
		description string
	}{
		{
			name:        "typical Milvus 2.x version",
			data:        []byte("version\x122.6.7"),
			wantVersion: "2.6.7",
			description: "Standard protobuf response with version field",
		},
		{
			name:        "version with v prefix",
			data:        []byte("version\x12v2.6.7"),
			wantVersion: "2.6.7",
			description: "Version with v prefix should be stripped",
		},
		{
			name:        "version with pre-release tag",
			data:        []byte("version\x122.6.7-beta.1"),
			wantVersion: "2.6.7-beta.1",
			description: "Version with pre-release tag should be preserved",
		},
		{
			name:        "version with build metadata",
			data:        []byte("version\x122.6.7+abc123"),
			wantVersion: "2.6.7",
			description: "Build metadata after + should not be captured",
		},
		{
			name:        "Milvus 1.x version",
			data:        []byte("version\x121.1.1"),
			wantVersion: "1.1.1",
			description: "Older 1.x version should be parsed",
		},
		{
			name:        "major version only",
			data:        []byte("version\x123"),
			wantVersion: "",
			description: "Single component version doesn't match semantic version pattern",
		},
		{
			name:        "major.minor version only",
			data:        []byte("version\x122.6"),
			wantVersion: "",
			description: "Two component version doesn't match semantic version pattern",
		},
		{
			name:        "four component version",
			data:        []byte("version\x122.6.7.1"),
			wantVersion: "2.6.7",
			description: "Regex only matches 3 components (major.minor.patch), .1 ignored",
		},
		{
			name:        "version zero",
			data:        []byte("version\x120.0.0"),
			wantVersion: "0.0.0",
			description: "Zero version should be valid",
		},
		{
			name:        "large version numbers",
			data:        []byte("version\x1299.88.77"),
			wantVersion: "99.88.77",
			description: "Large version numbers should be parsed",
		},
		{
			name:        "version with alpha pre-release",
			data:        []byte("version\x122.6.7-alpha"),
			wantVersion: "2.6.7-alpha",
			description: "Alpha pre-release should be captured",
		},
		{
			name:        "version with rc pre-release",
			data:        []byte("version\x122.6.7-rc.2"),
			wantVersion: "2.6.7-rc.2",
			description: "Release candidate should be captured",
		},
		{
			name:        "version with complex pre-release",
			data:        []byte("version\x122.6.7-beta.1.2.3"),
			wantVersion: "2.6.7-beta.1.2.3",
			description: "Complex pre-release notation should be captured",
		},
		{
			name:        "no version field",
			data:        []byte("other_field\x12some_value"),
			wantVersion: "",
			description: "Response without version should return empty string",
		},
		{
			name:        "empty protobuf",
			data:        []byte{},
			wantVersion: "",
			description: "Empty data should return empty string",
		},
		{
			name:        "malformed protobuf",
			data:        []byte{0xff, 0xff, 0xff},
			wantVersion: "",
			description: "Malformed protobuf should return empty string",
		},
		{
			name:        "version in longer response",
			data:        []byte("timestamp\x08123456789\x12version\x122.6.7\x1aother_data"),
			wantVersion: "2.6.7",
			description: "Version should be found in longer protobuf message",
		},
		{
			name:        "multiple version-like strings",
			data:        []byte("old_version\x121.0.0\x12version\x122.6.7"),
			wantVersion: "1.0.0",
			description: "First version match should be returned",
		},
		{
			name:        "version with v prefix uppercase",
			data:        []byte("version\x12V2.6.7"),
			wantVersion: "2.6.7",
			description: "Uppercase V prefix should be handled (regex doesn't match uppercase V)",
		},
		{
			name:        "version with leading whitespace",
			data:        []byte("version\x12  2.6.7"),
			wantVersion: "2.6.7",
			description: "Leading whitespace should not prevent match",
		},
		{
			name:        "version with trailing whitespace",
			data:        []byte("version\x122.6.7  "),
			wantVersion: "2.6.7",
			description: "Trailing whitespace should not prevent match",
		},
		{
			name:        "version in middle of string",
			data:        []byte("The current version is 2.6.7 release"),
			wantVersion: "2.6.7",
			description: "Version should be extracted from descriptive text",
		},
		{
			name:        "version with mixed pre-release and metadata",
			data:        []byte("version\x122.6.7-rc.1+build.123"),
			wantVersion: "2.6.7-rc.1",
			description: "Pre-release captured but metadata ignored",
		},
		{
			name:        "non-semantic version numbers",
			data:        []byte("port\x0819530"),
			wantVersion: "",
			description: "Non-semantic version numbers should not match",
		},
		{
			name:        "version with dashes in pre-release",
			data:        []byte("version\x122.6.7-beta-fixes-final"),
			wantVersion: "2.6.7-beta",
			description: "Regex stops at first non-alphanumeric after hyphen (hyphens not in character class)",
		},
		{
			name:        "version with dots in pre-release",
			data:        []byte("version\x122.6.7-0.3.7"),
			wantVersion: "2.6.7-0.3.7",
			description: "Dots in pre-release should be captured",
		},
		{
			name:        "version with underscore (non-standard)",
			data:        []byte("version\x122_6_7"),
			wantVersion: "",
			description: "Underscore separators should not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseVersionFromProtobuf(tt.data)

			if result != tt.wantVersion {
				t.Errorf("parseVersionFromProtobuf() = %q, want %q\nDescription: %s",
					result, tt.wantVersion, tt.description)
			}
		})
	}
}

// TestBuildMilvusCPE tests CPE generation for Milvus
func TestBuildMilvusCPE(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		wantCPE     string
		description string
	}{
		{
			name:        "Milvus 2.6.7",
			version:     "2.6.7",
			wantCPE:     "cpe:2.3:a:milvus:milvus:2.6.7:*:*:*:*:*:*:*",
			description: "Standard version should generate CPE with version",
		},
		{
			name:        "Milvus 2.0.0",
			version:     "2.0.0",
			wantCPE:     "cpe:2.3:a:milvus:milvus:2.0.0:*:*:*:*:*:*:*",
			description: "Major release should generate CPE with version",
		},
		{
			name:        "Milvus 1.1.1",
			version:     "1.1.1",
			wantCPE:     "cpe:2.3:a:milvus:milvus:1.1.1:*:*:*:*:*:*:*",
			description: "Older 1.x version should generate CPE with version",
		},
		{
			name:        "unknown version (wildcard)",
			version:     "",
			wantCPE:     "cpe:2.3:a:milvus:milvus:*:*:*:*:*:*:*:*",
			description: "Empty version should generate wildcard CPE",
		},
		{
			name:        "version with pre-release",
			version:     "2.6.7-beta",
			wantCPE:     "cpe:2.3:a:milvus:milvus:2.6.7-beta:*:*:*:*:*:*:*",
			description: "Pre-release version should be preserved in CPE",
		},
		{
			name:        "version with rc tag",
			version:     "2.6.7-rc.1",
			wantCPE:     "cpe:2.3:a:milvus:milvus:2.6.7-rc.1:*:*:*:*:*:*:*",
			description: "Release candidate should be preserved in CPE",
		},
		{
			name:        "version with alpha tag",
			version:     "2.6.7-alpha.2",
			wantCPE:     "cpe:2.3:a:milvus:milvus:2.6.7-alpha.2:*:*:*:*:*:*:*",
			description: "Alpha version should be preserved in CPE",
		},
		{
			name:        "single component version",
			version:     "2",
			wantCPE:     "cpe:2.3:a:milvus:milvus:2:*:*:*:*:*:*:*",
			description: "Single component version should be valid in CPE",
		},
		{
			name:        "two component version",
			version:     "2.6",
			wantCPE:     "cpe:2.3:a:milvus:milvus:2.6:*:*:*:*:*:*:*",
			description: "Two component version should be valid in CPE",
		},
		{
			name:        "four component version",
			version:     "2.6.7.1",
			wantCPE:     "cpe:2.3:a:milvus:milvus:2.6.7.1:*:*:*:*:*:*:*",
			description: "Four component version should be valid in CPE",
		},
		{
			name:        "version with v prefix (non-standard)",
			version:     "v2.6.7",
			wantCPE:     "cpe:2.3:a:milvus:milvus:v2.6.7:*:*:*:*:*:*:*",
			description: "v prefix should be preserved in CPE (caller should normalize)",
		},
		{
			name:        "zero version",
			version:     "0.0.0",
			wantCPE:     "cpe:2.3:a:milvus:milvus:0.0.0:*:*:*:*:*:*:*",
			description: "Zero version should generate valid CPE",
		},
		{
			name:        "large version numbers",
			version:     "99.88.77",
			wantCPE:     "cpe:2.3:a:milvus:milvus:99.88.77:*:*:*:*:*:*:*",
			description: "Large version numbers should generate valid CPE",
		},
		{
			name:        "version with complex pre-release",
			version:     "2.6.7-beta.1.2.3",
			wantCPE:     "cpe:2.3:a:milvus:milvus:2.6.7-beta.1.2.3:*:*:*:*:*:*:*",
			description: "Complex pre-release should be preserved in CPE",
		},
		{
			name:        "version with leading whitespace",
			version:     "  2.6.7",
			wantCPE:     "cpe:2.3:a:milvus:milvus:  2.6.7:*:*:*:*:*:*:*",
			description: "Leading whitespace preserved (caller should trim)",
		},
		{
			name:        "version with trailing whitespace",
			version:     "2.6.7  ",
			wantCPE:     "cpe:2.3:a:milvus:milvus:2.6.7  :*:*:*:*:*:*:*",
			description: "Trailing whitespace preserved (caller should trim)",
		},
		{
			name:        "version with special characters",
			version:     "2.6.7+build.123",
			wantCPE:     "cpe:2.3:a:milvus:milvus:2.6.7+build.123:*:*:*:*:*:*:*",
			description: "Special characters in version should be preserved",
		},
		{
			name:        "very long version string",
			version:     "2.6.7-beta.1.2.3.4.5+build.123456.commit.abcdef0123456789",
			wantCPE:     "cpe:2.3:a:milvus:milvus:2.6.7-beta.1.2.3.4.5+build.123456.commit.abcdef0123456789:*:*:*:*:*:*:*",
			description: "Very long version string should be handled",
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

// TestMilvusPluginInterface tests the plugin interface methods
func TestMilvusPluginInterface(t *testing.T) {
	plugin := &MilvusPlugin{}

	t.Run("Name", func(t *testing.T) {
		if name := plugin.Name(); name != MILVUS {
			t.Errorf("Name() = %q, want %q", name, MILVUS)
		}
	})

	t.Run("Type", func(t *testing.T) {
		if pluginType := plugin.Type(); pluginType != plugins.TCP {
			t.Errorf("Type() = %v, want TCP (%v)", pluginType, plugins.TCP)
		}
	})

	t.Run("Priority", func(t *testing.T) {
		priority := plugin.Priority()
		if priority != 50 {
			t.Errorf("Priority() = %d, want 50", priority)
		}
	})

	t.Run("PortPriority default port 19530", func(t *testing.T) {
		if !plugin.PortPriority(19530) {
			t.Error("PortPriority(19530) = false, want true")
		}
	})

	t.Run("PortPriority non-default port 8080", func(t *testing.T) {
		if plugin.PortPriority(8080) {
			t.Error("PortPriority(8080) = true, want false")
		}
	})

	t.Run("PortPriority non-default port 9091 (metrics)", func(t *testing.T) {
		if plugin.PortPriority(9091) {
			t.Error("PortPriority(9091) = true, want false (metrics port not priority)")
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
