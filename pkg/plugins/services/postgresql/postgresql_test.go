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

package postgres

import (
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/test"
)

// TestParseParameterStatus tests parsing of PostgreSQL ParameterStatus messages
func TestParseParameterStatus(t *testing.T) {
	tests := []struct {
		name      string
		msg       []byte
		wantName  string
		wantValue string
		wantErr   bool
	}{
		{
			name: "server_version parameter",
			msg: []byte{
				0x53,                   // Message type 'S'
				0x00, 0x00, 0x00, 0x1D, // Length: 29 bytes
				// "server_version\0"
				0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x76,
				0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00,
				// "14.5\0"
				0x31, 0x34, 0x2e, 0x35, 0x00,
			},
			wantName:  "server_version",
			wantValue: "14.5",
			wantErr:   false,
		},
		{
			name: "application_name parameter",
			msg: []byte{
				0x53,                   // Message type 'S'
				0x00, 0x00, 0x00, 0x19, // Length: 25 bytes
				// "application_name\0"
				0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74,
				0x69, 0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x00,
				// "psql\0"
				0x70, 0x73, 0x71, 0x6c, 0x00,
			},
			wantName:  "application_name",
			wantValue: "psql",
			wantErr:   false,
		},
		{
			name: "client_encoding parameter",
			msg: []byte{
				0x53,                   // Message type 'S'
				0x00, 0x00, 0x00, 0x17, // Length: 23 bytes
				// "client_encoding\0"
				0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x65,
				0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00,
				// "UTF8\0"
				0x55, 0x54, 0x46, 0x38, 0x00,
			},
			wantName:  "client_encoding",
			wantValue: "UTF8",
			wantErr:   false,
		},
		{
			name:      "message too short",
			msg:       []byte{0x53, 0x00},
			wantName:  "",
			wantValue: "",
			wantErr:   true,
		},
		{
			name: "wrong message type",
			msg: []byte{
				0x52,                   // Wrong type ('R' instead of 'S')
				0x00, 0x00, 0x00, 0x08,
				0x00, 0x00, 0x00, 0x00,
			},
			wantName:  "",
			wantValue: "",
			wantErr:   true,
		},
		{
			name: "missing null terminators",
			msg: []byte{
				0x53,                   // Message type 'S'
				0x00, 0x00, 0x00, 0x10, // Length
				// "server_version" (no null terminator)
				0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x76,
				0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
			},
			wantName:  "",
			wantValue: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotValue, err := parseParameterStatus(tt.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseParameterStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotName != tt.wantName {
				t.Errorf("parseParameterStatus() gotName = %v, want %v", gotName, tt.wantName)
			}
			if gotValue != tt.wantValue {
				t.Errorf("parseParameterStatus() gotValue = %v, want %v", gotValue, tt.wantValue)
			}
		})
	}
}

// TestBuildPostgreSQLCPE tests CPE generation for PostgreSQL
func TestBuildPostgreSQLCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "version 14.5",
			version: "14.5",
			want:    "cpe:2.3:a:postgresql:postgresql:14.5:*:*:*:*:*:*:*",
		},
		{
			name:    "version 16.1",
			version: "16.1",
			want:    "cpe:2.3:a:postgresql:postgresql:16.1:*:*:*:*:*:*:*",
		},
		{
			name:    "version 17.2",
			version: "17.2",
			want:    "cpe:2.3:a:postgresql:postgresql:17.2:*:*:*:*:*:*:*",
		},
		{
			name:    "version 9.6.24",
			version: "9.6.24",
			want:    "cpe:2.3:a:postgresql:postgresql:9.6.24:*:*:*:*:*:*:*",
		},
		{
			name:    "unknown version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildPostgreSQLCPE(tt.version)
			if got != tt.want {
				t.Errorf("buildPostgreSQLCPE() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPostgreSQL(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "postgresql",
			Port:        5432,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "postgres",
				Env: []string{
					"POSTGRES_PASSWORD=secret",
					"POSTGRES_USER=user_name",
					"POSTGRES_DB=dbname",
					"listen_addresses = '*'",
				},
			},
		},
	}

	p := &POSTGRESPlugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("%s", err.Error())
			}
		})
	}
}
