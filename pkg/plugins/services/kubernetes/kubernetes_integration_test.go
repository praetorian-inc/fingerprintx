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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

// TestKubernetesPlugin_Run_StatusCodeHandling tests that the plugin correctly handles
// HTTP status codes and only detects Kubernetes when status is 200 OK
func TestKubernetesPlugin_Run_StatusCodeHandling(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		responseBody   string
		expectDetected bool
	}{
		{
			name:       "200 OK with valid version response should detect",
			statusCode: http.StatusOK,
			responseBody: `{
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
			expectDetected: true,
		},
		{
			name:       "401 Unauthorized should NOT detect (anonymous access disabled)",
			statusCode: http.StatusUnauthorized,
			responseBody: `{
				"kind": "Status",
				"apiVersion": "v1",
				"status": "Failure",
				"message": "Unauthorized",
				"reason": "Unauthorized",
				"code": 401
			}`,
			expectDetected: false,
		},
		{
			name:       "403 Forbidden should NOT detect (public-info-viewer disabled)",
			statusCode: http.StatusForbidden,
			responseBody: `{
				"kind": "Status",
				"apiVersion": "v1",
				"status": "Failure",
				"message": "forbidden: User \"system:anonymous\" cannot get path \"/version\"",
				"reason": "Forbidden",
				"code": 403
			}`,
			expectDetected: false,
		},
		{
			name:           "404 Not Found should NOT detect (endpoint doesn't exist)",
			statusCode:     http.StatusNotFound,
			responseBody:   `{"error": "not found"}`,
			expectDetected: false,
		},
		{
			name:           "500 Internal Server Error should NOT detect",
			statusCode:     http.StatusInternalServerError,
			responseBody:   `{"error": "internal server error"}`,
			expectDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test HTTPS server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request path
				if r.URL.Path != "/version" {
					t.Errorf("unexpected request path: %s, expected /version", r.URL.Path)
				}

				// Return configured status and body
				w.WriteHeader(tt.statusCode)
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tt.responseBody)
			}))
			defer server.Close()

			// Dial the test server with raw TCP (plugin will wrap with TLS)
			serverAddr := server.Listener.Addr().String()
			conn, err := net.Dial("tcp", serverAddr)
			if err != nil {
				t.Fatalf("failed to dial test server: %v", err)
			}
			defer conn.Close()

			// Run the plugin
			plugin := &KubernetesPlugin{}
			timeout := 5 * time.Second
			target := plugins.Target{}

			result, err := plugin.Run(conn, timeout, target)

			// Verify detection result matches expectation
			if tt.expectDetected {
				if result == nil {
					t.Errorf("expected detection but got nil result")
				}
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
				if result != nil && result.Protocol != KUBERNETES {
					t.Errorf("expected protocol 'kubernetes' but got: %s", result.Protocol)
				}
			} else {
				// For non-200 status codes, plugin should return nil, nil (no detection)
				if result != nil {
					t.Errorf("expected no detection (nil result) but got: %+v", result)
				}
			}
		})
	}
}
