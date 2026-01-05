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

package pinecone

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

// PINECONEPlugin detects Pinecone Vector Database instances.
//
// Detection Strategy:
// Pinecone is a managed vector database (SaaS) that runs on HTTPS (port 443).
// When an unauthenticated request is sent to a Pinecone endpoint, the service
// returns a 401 Unauthorized response with Pinecone-specific headers:
//   - x-pinecone-api-version (PRIMARY marker - unique to Pinecone)
//   - x-pinecone-auth-rejected-reason (SECONDARY marker)
//
// This approach is similar to MySQL error packet detection - the service
// identifies itself in rejection responses without requiring valid credentials.
//
// Version Detection:
// The x-pinecone-api-version header contains the API version (e.g., "2025-01"),
// not the internal Pinecone service version. Since Pinecone is closed-source SaaS,
// the internal version cannot be determined. Therefore, the CPE uses a wildcard
// version: cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*
type PINECONEPlugin struct{}

const (
	PROTOCOL_NAME = "pinecone"
	DEFAULT_PORT  = 443
	USERAGENT     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

	// Header constants for detection
	HEADER_API_VERSION      = "X-Pinecone-Api-Version"
	HEADER_AUTH_REJECTED    = "X-Pinecone-Auth-Rejected-Reason"
)

func init() {
	plugins.RegisterPlugin(&PINECONEPlugin{})
}

// Run performs Pinecone detection via 401 response header analysis.
//
// Phase 1: Detection
//   - Send unauthenticated HTTPS GET request
//   - Receive 401 Unauthorized response
//   - Check for x-pinecone-api-version header (PRIMARY)
//   - Check for x-pinecone-auth-rejected-reason header (SECONDARY fallback)
//
// Phase 2: Enrichment
//   - Extract API version from header value
//   - Store as metadata (not used in CPE due to API vs service version distinction)
//
// Returns:
//   - *plugins.Service with Pinecone detection if headers present
//   - nil if not detected
//   - error on request failures (connection issues, timeouts)
func (p *PINECONEPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Build HTTPS GET request (unauthenticated)
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s", conn.RemoteAddr().String()), nil)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil, nil
		}
		return nil, &utils.RequestError{Message: err.Error()}
	}

	// Use target host if provided (important for virtual hosting)
	if target.Host != "" {
		req.Host = target.Host
	}

	// Create HTTPS client with custom dialer to reuse the TLS connection
	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		// Don't follow redirects - we want the original 401 response
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req.Header.Set("User-Agent", USERAGENT)

	// Send request and receive response
	resp, err := client.Do(req)
	if err != nil {
		return nil, &utils.RequestError{Message: err.Error()}
	}
	defer resp.Body.Close()

	// Phase 1: Detection - Check for Pinecone-specific headers
	apiVersion := resp.Header.Get(HEADER_API_VERSION)
	authRejected := resp.Header.Get(HEADER_AUTH_REJECTED)

	// PRIMARY detection: x-pinecone-api-version header (unique to Pinecone)
	if apiVersion != "" {
		return p.buildDetectionResult(target, resp, apiVersion, "high")
	}

	// SECONDARY detection: x-pinecone-auth-rejected-reason (fallback)
	if authRejected != "" {
		return p.buildDetectionResult(target, resp, "", "medium")
	}

	// Not a Pinecone instance
	return nil, nil
}

// buildDetectionResult constructs the Service object for detected Pinecone instances.
//
// CPE Format: cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*
//   - Version field is wildcard (*) because internal service version is unavailable
//   - Only API version (from header) is known, which represents API contract not service version
func (p *PINECONEPlugin) buildDetectionResult(
	target plugins.Target,
	resp *http.Response,
	apiVersion string,
	confidence string,
) (*plugins.Service, error) {
	// CPE with wildcard version (internal version unknown for closed-source SaaS)
	cpe := "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*"

	payload := plugins.ServicePinecone{
		CPEs: []string{cpe},
		// API version stored separately (not used in CPE)
		APIVersion: apiVersion,
	}

	// Version is wildcard, so pass empty string
	// isTLS=true since Pinecone is HTTPS-only
	return plugins.CreateServiceFrom(target, payload, true, "", plugins.TCPTLS), nil
}

// PortPriority returns true for port 443 (Pinecone's default HTTPS port).
func (p *PINECONEPlugin) PortPriority(port uint16) bool {
	return port == DEFAULT_PORT
}

// Name returns the protocol identifier.
func (p *PINECONEPlugin) Name() string {
	return PROTOCOL_NAME
}

// Type returns TCPTLS since Pinecone uses HTTPS.
func (p *PINECONEPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

// Priority returns 50, which runs after SSH/databases but before generic HTTPS.
//
// Priority ordering ensures:
//   - Pinecone-specific detection (50) runs before generic HTTPS (1)
//   - Database protocols run first (MongoDB -1, MySQL 0, etc.)
//   - Generic HTTP/HTTPS run last as catch-all
func (p *PINECONEPlugin) Priority() int {
	return 50
}
