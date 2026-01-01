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

package memcached

import (
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/test"
)

func TestMemcached(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "memcached",
			Port:        11211,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "memcached",
			},
		},
	}

	p := &MEMCACHEDPlugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

// TestCheckMemcachedVersionResponse tests validation of version command responses
func TestCheckMemcachedVersionResponse(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		wantOK   bool
	}{
		{
			name:     "valid version response",
			response: []byte("VERSION 1.6.22\r\n"),
			wantOK:   true,
		},
		{
			name:     "valid version response with different version",
			response: []byte("VERSION 1.5.22\r\n"),
			wantOK:   true,
		},
		{
			name:     "valid version response with older version",
			response: []byte("VERSION 1.4.39\r\n"),
			wantOK:   true,
		},
		{
			name:     "response too short",
			response: []byte("VER"),
			wantOK:   false,
		},
		{
			name:     "missing VERSION prefix",
			response: []byte("1.6.22\r\n"),
			wantOK:   false,
		},
		{
			name:     "missing CRLF suffix",
			response: []byte("VERSION 1.6.22"),
			wantOK:   false,
		},
		{
			name:     "ERROR response",
			response: []byte("ERROR\r\n"),
			wantOK:   false,
		},
		{
			name:     "empty response",
			response: []byte(""),
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOK, _ := checkMemcachedVersionResponse(tt.response)
			if gotOK != tt.wantOK {
				t.Errorf("checkMemcachedVersionResponse() gotOK = %v, want %v", gotOK, tt.wantOK)
			}
		})
	}
}

// TestCheckMemcachedStatsResponse tests validation of stats command responses
func TestCheckMemcachedStatsResponse(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		wantOK   bool
	}{
		{
			name: "valid stats response",
			response: []byte("STAT pid 1162\r\n" +
				"STAT version 1.6.22\r\n" +
				"STAT uptime 5022\r\n" +
				"END\r\n"),
			wantOK: true,
		},
		{
			name: "valid stats response with many fields",
			response: []byte("STAT pid 1162\r\n" +
				"STAT uptime 5022\r\n" +
				"STAT time 1415208270\r\n" +
				"STAT version 1.5.22\r\n" +
				"STAT curr_connections 5\r\n" +
				"STAT total_connections 6\r\n" +
				"END\r\n"),
			wantOK: true,
		},
		{
			name:     "response too short",
			response: []byte("STAT pid 1\r\n"),
			wantOK:   false,
		},
		{
			name:     "missing STAT lines",
			response: []byte("END\r\n"),
			wantOK:   false,
		},
		{
			name:     "missing END suffix",
			response: []byte("STAT pid 1162\r\n" + "STAT version 1.6.22\r\n"),
			wantOK:   false,
		},
		{
			name:     "empty response",
			response: []byte(""),
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOK, _ := checkMemcachedStatsResponse(tt.response)
			if gotOK != tt.wantOK {
				t.Errorf("checkMemcachedStatsResponse() gotOK = %v, want %v", gotOK, tt.wantOK)
			}
		})
	}
}

// TestExtractMemcachedVersion tests version extraction from version command response
func TestExtractMemcachedVersion(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		want     string
	}{
		{
			name:     "standard version response",
			response: []byte("VERSION 1.6.22\r\n"),
			want:     "1.6.22",
		},
		{
			name:     "version 1.5.x",
			response: []byte("VERSION 1.5.22\r\n"),
			want:     "1.5.22",
		},
		{
			name:     "version 1.4.x",
			response: []byte("VERSION 1.4.39\r\n"),
			want:     "1.4.39",
		},
		{
			name:     "version with extra whitespace",
			response: []byte("VERSION   1.6.22  \r\n"),
			want:     "1.6.22",
		},
		{
			name:     "empty response",
			response: []byte(""),
			want:     "",
		},
		{
			name:     "missing VERSION prefix",
			response: []byte("1.6.22\r\n"),
			want:     "",
		},
		{
			name:     "ERROR response",
			response: []byte("ERROR\r\n"),
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMemcachedVersion(tt.response)
			if got != tt.want {
				t.Errorf("extractMemcachedVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestExtractVersionFromStats tests version extraction from stats command response
func TestExtractVersionFromStats(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		want     string
	}{
		{
			name: "standard stats response",
			response: []byte("STAT pid 1162\r\n" +
				"STAT version 1.6.22\r\n" +
				"STAT uptime 5022\r\n" +
				"END\r\n"),
			want: "1.6.22",
		},
		{
			name: "version at end",
			response: []byte("STAT pid 1162\r\n" +
				"STAT uptime 5022\r\n" +
				"STAT curr_connections 5\r\n" +
				"STAT version 1.5.22\r\n" +
				"END\r\n"),
			want: "1.5.22",
		},
		{
			name: "version at beginning",
			response: []byte("STAT version 1.4.39\r\n" +
				"STAT pid 1162\r\n" +
				"STAT uptime 5022\r\n" +
				"END\r\n"),
			want: "1.4.39",
		},
		{
			name: "no version field",
			response: []byte("STAT pid 1162\r\n" +
				"STAT uptime 5022\r\n" +
				"END\r\n"),
			want: "",
		},
		{
			name:     "empty response",
			response: []byte(""),
			want:     "",
		},
		{
			name: "malformed version line",
			response: []byte("STAT pid 1162\r\n" +
				"STAT version\r\n" +
				"END\r\n"),
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractVersionFromStats(tt.response)
			if got != tt.want {
				t.Errorf("extractVersionFromStats() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBuildMemcachedCPE tests CPE generation for Memcached servers
func TestBuildMemcachedCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "specific version 1.6.x",
			version: "1.6.22",
			want:    "cpe:2.3:a:memcached:memcached:1.6.22:*:*:*:*:*:*:*",
		},
		{
			name:    "version 1.5.x",
			version: "1.5.22",
			want:    "cpe:2.3:a:memcached:memcached:1.5.22:*:*:*:*:*:*:*",
		},
		{
			name:    "version 1.4.x",
			version: "1.4.39",
			want:    "cpe:2.3:a:memcached:memcached:1.4.39:*:*:*:*:*:*:*",
		},
		{
			name:    "unknown version (wildcard)",
			version: "",
			want:    "cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*",
		},
		{
			name:    "version with patch number",
			version: "1.6.17",
			want:    "cpe:2.3:a:memcached:memcached:1.6.17:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildMemcachedCPE(tt.version)
			if got != tt.want {
				t.Errorf("buildMemcachedCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}
