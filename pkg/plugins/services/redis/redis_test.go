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

package redis

import (
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/test"
)

func TestRedis(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "redis",
			Port:        6379,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "redis",
			},
		},
	}

	p := &REDISPlugin{}

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

// TestExtractRedisVersion tests version extraction from INFO SERVER response
func TestExtractRedisVersion(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     string
	}{
		{
			name: "standard INFO response with version",
			response: "# Server\r\n" +
				"redis_version:7.4.0\r\n" +
				"redis_git_sha1:c9d29f6a\r\n" +
				"redis_mode:standalone\r\n",
			want: "7.4.0",
		},
		{
			name: "older Redis version",
			response: "# Server\r\n" +
				"redis_version:5.0.14\r\n" +
				"os:Linux 5.10.0\r\n",
			want: "5.0.14",
		},
		{
			name: "version 6.x",
			response: "redis_version:6.2.7\r\n" +
				"redis_mode:cluster\r\n",
			want: "6.2.7",
		},
		{
			name:     "empty response",
			response: "",
			want:     "",
		},
		{
			name: "missing version field",
			response: "# Server\r\n" +
				"redis_mode:standalone\r\n",
			want: "",
		},
		{
			name: "malformed response",
			response: "invalid response data",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRedisVersion(tt.response)
			if got != tt.want {
				t.Errorf("extractRedisVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBuildRedisCPE tests CPE generation for Redis servers
func TestBuildRedisCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "specific version",
			version: "7.4.0",
			want:    "cpe:2.3:a:redis:redis:7.4.0:*:*:*:*:*:*:*",
		},
		{
			name:    "older version",
			version: "5.0.14",
			want:    "cpe:2.3:a:redis:redis:5.0.14:*:*:*:*:*:*:*",
		},
		{
			name:    "version 6.x",
			version: "6.2.7",
			want:    "cpe:2.3:a:redis:redis:6.2.7:*:*:*:*:*:*:*",
		},
		{
			name:    "unknown version (wildcard)",
			version: "",
			want:    "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildRedisCPE(tt.version)
			if got != tt.want {
				t.Errorf("buildRedisCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}
