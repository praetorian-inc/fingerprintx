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

package elasticsearch

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

/*
Elasticsearch REST API Fingerprinting

This plugin implements Elasticsearch fingerprinting using the HTTP REST API.
Elasticsearch exposes cluster information at the root endpoint (/) which includes
version details and a unique tagline.

Detection Strategy:
  PHASE 1 - DETECTION (determines if the service is Elasticsearch):
    - HTTP GET request to / endpoint
    - Returns JSON response with cluster information
    - Unique tagline: "You Know, for Search" (only in Elasticsearch)
    - Distinguishes from OpenSearch (different tagline)

  PHASE 2 - ENRICHMENT (extracts version information):
    - Version available directly in JSON response: version.number
    - Format: X.Y.Z (semantic versioning)
    - Available in ALL Elasticsearch versions (1.x - 8.x)

Expected JSON Response Structure:
{
  "name" : "node-name",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "...",
  "version" : {
    "number" : "8.11.3",
    "build_flavor" : "default",
    "build_type" : "docker",
    "build_hash" : "...",
    "build_date" : "...",
    "build_snapshot" : false,
    "lucene_version" : "9.8.0",
    "minimum_wire_compatibility_version" : "7.17.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "You Know, for Search"
}

Version Compatibility:
  - Elasticsearch 1.x - 8.x: All versions return tagline and version
  - OpenSearch 1.x, 2.x: Different tagline ("The OpenSearch Project: ...")
*/

const (
	ELASTICSEARCH         = "elasticsearch"
	DefaultElasticsearchPort = 9200
	ElasticsearchTagline  = "You Know, for Search"
)

// elasticsearchRootResponse represents the JSON response from Elasticsearch root endpoint
type elasticsearchRootResponse struct {
	Name        string               `json:"name"`
	ClusterName string               `json:"cluster_name"`
	ClusterUUID string               `json:"cluster_uuid"`
	Version     elasticsearchVersion `json:"version"`
	Tagline     string               `json:"tagline"`
}

// elasticsearchVersion represents the version object in Elasticsearch response
type elasticsearchVersion struct {
	Number        string `json:"number"`
	BuildFlavor   string `json:"build_flavor"`
	BuildType     string `json:"build_type"`
	BuildHash     string `json:"build_hash"`
	BuildDate     string `json:"build_date"`
	BuildSnapshot bool   `json:"build_snapshot"`
	LuceneVersion string `json:"lucene_version"`
}

type ElasticsearchPlugin struct{}

func init() {
	plugins.RegisterPlugin(&ElasticsearchPlugin{})
}

// versionCleanupRegex removes -SNAPSHOT suffix from versions
var versionCleanupRegex = regexp.MustCompile(`^(\d+\.\d+\.\d+)(-SNAPSHOT)?$`)

// detectElasticsearch performs HTTP detection of Elasticsearch service.
// Returns version string (empty if not found) and detection success boolean.
func detectElasticsearch(conn net.Conn, timeout time.Duration) (string, bool, error) {
	// Build HTTP GET request to root endpoint
	httpRequest := "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

	// Send HTTP request and receive response
	response, err := utils.SendRecv(conn, []byte(httpRequest), timeout)
	if err != nil {
		return "", false, err
	}
	if len(response) == 0 {
		return "", false, &utils.InvalidResponseError{Service: ELASTICSEARCH}
	}

	// Parse HTTP response
	responseStr := string(response)

	// Check for HTTP 200 OK status
	if !strings.Contains(responseStr, "HTTP/1.1 200") && !strings.Contains(responseStr, "HTTP/1.0 200") {
		// Not a successful response, not Elasticsearch
		return "", false, nil
	}

	// Extract JSON body from HTTP response
	// HTTP response format: headers\r\n\r\nbody
	bodyStart := strings.Index(responseStr, "\r\n\r\n")
	if bodyStart == -1 {
		return "", false, &utils.InvalidResponseError{Service: ELASTICSEARCH}
	}
	jsonBody := responseStr[bodyStart+4:]

	// Parse JSON response
	var esResponse elasticsearchRootResponse
	err = json.Unmarshal([]byte(jsonBody), &esResponse)
	if err != nil {
		// Not valid JSON or not Elasticsearch format
		return "", false, nil
	}

	// Primary detection: Check for Elasticsearch tagline
	if esResponse.Tagline != ElasticsearchTagline {
		// Not Elasticsearch (could be OpenSearch or other service)
		return "", false, nil
	}

	// Secondary validation: Ensure version object exists
	if esResponse.Version.Number == "" {
		// Tagline matches but no version - suspicious, still detect as Elasticsearch
		return "", true, nil
	}

	// Clean up version string (remove -SNAPSHOT suffix if present)
	version := cleanVersionString(esResponse.Version.Number)

	// Successfully detected Elasticsearch with version
	return version, true, nil
}

// cleanVersionString removes -SNAPSHOT suffix from version strings.
// Preserves RC tags (e.g., "8.0.0-rc2" remains as-is).
func cleanVersionString(version string) string {
	// Handle SNAPSHOT builds: "8.11.3-SNAPSHOT" → "8.11.3"
	if strings.HasSuffix(version, "-SNAPSHOT") {
		version = strings.TrimSuffix(version, "-SNAPSHOT")
	}
	return version
}

// buildElasticsearchCPE generates a CPE (Common Platform Enumeration) string for Elasticsearch.
// CPE format: cpe:2.3:a:elastic:elasticsearch:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to match Wappalyzer/RMI/FTP
// plugin behavior and enable asset inventory use cases.
func buildElasticsearchCPE(version string) string {
	// Elasticsearch product is always known when this is called, so always generate CPE
	if version == "" {
		version = "*" // Unknown version, but known product
	}
	return fmt.Sprintf("cpe:2.3:a:elastic:elasticsearch:%s:*:*:*:*:*:*:*", version)
}

func (p *ElasticsearchPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	version, detected, err := detectElasticsearch(conn, timeout)
	if err != nil {
		return nil, err
	}
	if !detected {
		return nil, nil
	}

	// Elasticsearch detected - create service payload
	cpe := buildElasticsearchCPE(version)
	payload := plugins.ServiceElasticsearch{
		CPEs: []string{cpe},
	}

	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *ElasticsearchPlugin) PortPriority(port uint16) bool {
	return port == DefaultElasticsearchPort
}

func (p *ElasticsearchPlugin) Name() string {
	return ELASTICSEARCH
}

func (p *ElasticsearchPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *ElasticsearchPlugin) Priority() int {
	return 100
}
