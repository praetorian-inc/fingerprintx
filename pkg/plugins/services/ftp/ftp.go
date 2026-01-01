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

package ftp

import (
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

// FTP protocol constants
const (
	FTP                  = "ftp"
	DefaultFTPPort       = 21
	FTPWelcomeResponseRe = `^220[- ]` // FTP 220 response code (service ready)
)

var ftpResponse = regexp.MustCompile(`^\d{3}[- ](.*)\r`)

// FTP keyword whitelist pattern - matches FTP, FTPD, "FTP server", "FTP service" (case-insensitive)
// This is the core of the whitelist approach to prevent SMTP false positives (PR #44 fix)
var ftpKeywordPattern = regexp.MustCompile(`(?i)(ftpd?|ftp\s+(server|service))`)

// ftpWelcomePattern matches FTP 220 welcome responses
var ftpWelcomePattern = regexp.MustCompile(FTPWelcomeResponseRe)

// Version extraction patterns for known FTP servers (requires version in banner)
var versionPatterns = []struct {
	server  string
	pattern *regexp.Regexp
}{
	{"vsftpd", regexp.MustCompile(`\(vsFTPd\s+([0-9.]+)\)`)},
	{"ProFTPD", regexp.MustCompile(`ProFTPD\s+([0-9.]+[a-z]?)\s+Server`)},
	{"Pure-FTPd", regexp.MustCompile(`(?i)Pure-?FTPd\s+([0-9.]+)`)},
	{"FileZilla", regexp.MustCompile(`FileZilla Server version\s+([0-9.]+)`)},
	{"Microsoft IIS", regexp.MustCompile(`Microsoft FTP Service\s*\(Version\s+([0-9.]+)\)`)},
	{"wu-ftpd", regexp.MustCompile(`Version wu-([0-9.-]+)`)},
	{"Generic", regexp.MustCompile(`Version\s+([0-9.]+)`)},
}

// Server identification patterns (no version required, used as fallback)
var serverPatterns = []struct {
	server  string
	pattern *regexp.Regexp
}{
	{"vsftpd", regexp.MustCompile(`(?i)vsFTPd`)},
	{"ProFTPD", regexp.MustCompile(`(?i)ProFTPD`)},
	{"Pure-FTPd", regexp.MustCompile(`(?i)Pure-?FTPd`)},
	{"FileZilla", regexp.MustCompile(`(?i)FileZilla`)},
	{"Microsoft IIS", regexp.MustCompile(`(?i)Microsoft FTP`)},
	{"wu-ftpd", regexp.MustCompile(`(?i)wu-[0-9]`)},
}

// CPE vendor mappings for known FTP servers
var cpeVendors = map[string]string{
	"vsftpd":        "cpe:2.3:a:vsftpd:vsftpd:%s:*:*:*:*:*:*:*",
	"ProFTPD":       "cpe:2.3:a:proftpd:proftpd:%s:*:*:*:*:*:*:*",
	"Pure-FTPd":     "cpe:2.3:a:pureftpd:pure-ftpd:%s:*:*:*:*:*:*:*",
	"FileZilla":     "cpe:2.3:a:filezilla-project:filezilla_server:%s:*:*:*:*:*:*:*",
	"Microsoft IIS": "cpe:2.3:a:microsoft:ftp_service:%s:*:*:*:*:*:*:*",
}

type FTPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&FTPPlugin{})
}

// isFTPBanner determines if a banner indicates FTP service and returns confidence level.
// Detection strategy (whitelist approach):
//   - HIGH confidence: Port 21 + FTP keyword match
//   - MEDIUM confidence: Non-standard port + FTP keyword match
//   - LOW confidence: Port 21 + No FTP keyword (heuristic fallback)
//   - REJECT: No detection if no FTP keywords on non-21 ports (prevents SMTP false positives)
//
// Parameters:
//   - banner: The server banner string
//   - port: The port number being scanned
//
// Returns:
//   - bool: true if FTP detected, false otherwise
//   - string: confidence level ("high", "medium", "low", or "" if rejected)
func isFTPBanner(banner string, port uint16) (bool, string) {
	// Phase 1: Check for explicit FTP keywords (WHITELIST)
	if ftpKeywordPattern.MatchString(banner) {
		if port == DefaultFTPPort {
			return true, "high"
		}
		return true, "medium"
	}

	// Phase 2: Port 21 heuristic (relaxed detection on default port)
	// Check for 220 response code specifically (welcome message, not errors)
	if port == DefaultFTPPort && ftpWelcomePattern.MatchString(banner) {
		return true, "low"
	}

	// Phase 3: Reject detection (no FTP keywords on non-FTP ports)
	// This prevents false positives on SMTP ports (25, 587, 465)
	return false, ""
}

// extractFTPVersion extracts FTP server type and version from banner.
// Attempts to match against known FTP server patterns in order of specificity.
// If version cannot be extracted but server is identified, returns server with empty version.
//
// Parameters:
//   - banner: The FTP banner string
//
// Returns:
//   - string: Server type (e.g., "vsftpd", "ProFTPD") or empty if not found
//   - string: Version string (e.g., "2.0.1") or empty if not found
func extractFTPVersion(banner string) (string, string) {
	// Phase 1: Try to extract server AND version
	for _, vp := range versionPatterns {
		matches := vp.pattern.FindStringSubmatch(banner)
		if len(matches) >= 2 {
			return vp.server, matches[1]
		}
	}

	// Phase 2: Fallback - identify server without version (for CPE with * version)
	for _, sp := range serverPatterns {
		if sp.pattern.MatchString(banner) {
			return sp.server, ""
		}
	}

	// No server identified
	return "", ""
}

// buildFTPCPE generates a CPE (Common Platform Enumeration) string for FTP servers.
// CPE format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
//
// When version is unknown but server is identified, uses "*" for version field
// to match Wappalyzer/RMI plugin behavior and enable asset inventory use cases.
//
// Parameters:
//   - server: Server type (e.g., "vsftpd", "ProFTPD")
//   - version: Version string (e.g., "2.0.1"), or empty for unknown
//
// Returns:
//   - string: CPE string, or empty if server is unknown
func buildFTPCPE(server, version string) string {
	if server == "" {
		return ""
	}
	if version == "" {
		version = "*" // Unknown version, but known product (matches RMI/Wappalyzer pattern)
	}

	// Look up CPE template for this server
	cpeTemplate, exists := cpeVendors[server]
	if !exists {
		return ""
	}

	// Format CPE with version
	return fmt.Sprintf(cpeTemplate, version)
}

func (p *FTPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	banner := string(response)

	// Phase 1: Detection - Determine if this is FTP using whitelist approach
	port := target.Address.Port()
	detected, confidence := isFTPBanner(banner, port)
	if !detected {
		return nil, nil
	}

	// Phase 2: Enrichment - Extract version and generate CPE
	server, version := extractFTPVersion(banner)
	cpe := buildFTPCPE(server, version)

	// Create service payload with enriched metadata
	payload := plugins.ServiceFTP{
		Banner:     banner,
		Confidence: confidence,
	}

	// Add CPE if available
	if cpe != "" {
		payload.CPEs = []string{cpe}
	}

	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *FTPPlugin) PortPriority(i uint16) bool {
	return i == DefaultFTPPort
}

func (p *FTPPlugin) Name() string {
	return FTP
}

func (p *FTPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *FTPPlugin) Priority() int {
	return 10
}
