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

package mysql

import (
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/test"
	"github.com/stretchr/testify/assert"
)

func TestMySQL(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "mysql",
			Port:        3306,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "mysql",
				Tag:        "5.7.39",
				Env: []string{
					"MYSQL_ROOT_PASSWORD=my-secret-pw",
				},
			},
		},
	}

	p := &MYSQLPlugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

// TestParseVersionString tests the parseVersionString function for various MySQL-family version strings.
func TestParseVersionString(t *testing.T) {
	tests := []struct {
		name           string
		versionStr     string
		wantServerType string
		wantVersion    string
	}{
		// MySQL (Oracle)
		{"MySQL 8.0.28", "8.0.28", "mysql", "8.0.28"},
		{"MySQL 5.7.40", "5.7.40", "mysql", "5.7.40"},
		{"MySQL 8.0.28 with distro", "8.0.28-0ubuntu0.20.04.3", "mysql", "8.0.28"},
		{"MySQL 5.6.51", "5.6.51", "mysql", "5.6.51"},

		// MariaDB
		{"MariaDB 10.5.12", "10.5.12-MariaDB", "mariadb", "10.5.12"},
		{"MariaDB 11.0.3", "11.0.3-MariaDB-1:11.0.3+maria~ubu2204", "mariadb", "11.0.3"},
		{"MariaDB with legacy prefix", "5.5.5-10.5.12-MariaDB", "mariadb", "10.5.12"},
		{"MariaDB 10.4.7", "10.4.7-MariaDB", "mariadb", "10.4.7"},
		{"MariaDB 10.5.19 with distro", "10.5.19-MariaDB-0+deb11u2", "mariadb", "10.5.19"},

		// Percona Server
		{"Percona 8.0.28-19", "8.0.28-19-Percona", "percona", "8.0.28-19"},
		{"Percona 5.7.40-43", "5.7.40-43-Percona", "percona", "5.7.40-43"},
		{"Percona 8.0.28-20", "8.0.28-20-Percona Server", "percona", "8.0.28-20"},

		// Amazon Aurora MySQL
		{"Aurora MySQL 3.x", "8.0.mysql_aurora.3.11.0", "aurora", "3.11.0"},
		{"Aurora MySQL 2.x", "5.7.mysql_aurora.2.11.0", "aurora", "2.11.0"},

		// Edge cases
		{"Empty string", "", "unknown", ""},
		{"Invalid format", "not-a-version", "unknown", ""},
		{"Random text", "random text without version", "unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverType, version := parseVersionString(tt.versionStr)
			assert.Equal(t, tt.wantServerType, serverType, "server type mismatch")
			assert.Equal(t, tt.wantVersion, version, "version mismatch")
		})
	}
}

// TestBuildMySQLCPE tests the buildMySQLCPE function for generating correct CPE strings.
func TestBuildMySQLCPE(t *testing.T) {
	tests := []struct {
		name       string
		serverType string
		version    string
		wantCPE    string
	}{
		// MySQL
		{"MySQL with version", "mysql", "8.0.28", "cpe:2.3:a:oracle:mysql:8.0.28:*:*:*:*:*:*:*"},
		{"MySQL 5.7.40", "mysql", "5.7.40", "cpe:2.3:a:oracle:mysql:5.7.40:*:*:*:*:*:*:*"},
		{"MySQL wildcard version", "mysql", "", "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"},

		// MariaDB
		{"MariaDB with version", "mariadb", "10.5.12", "cpe:2.3:a:mariadb:mariadb:10.5.12:*:*:*:*:*:*:*"},
		{"MariaDB 11.0.3", "mariadb", "11.0.3", "cpe:2.3:a:mariadb:mariadb:11.0.3:*:*:*:*:*:*:*"},
		{"MariaDB wildcard version", "mariadb", "", "cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*"},

		// Percona
		{"Percona with version", "percona", "8.0.28-19", "cpe:2.3:a:percona:percona_server:8.0.28-19:*:*:*:*:*:*:*"},
		{"Percona 5.7.40-43", "percona", "5.7.40-43", "cpe:2.3:a:percona:percona_server:5.7.40-43:*:*:*:*:*:*:*"},
		{"Percona wildcard version", "percona", "", "cpe:2.3:a:percona:percona_server:*:*:*:*:*:*:*:*"},

		// Aurora
		{"Aurora with version", "aurora", "3.11.0", "cpe:2.3:a:amazon:aurora:3.11.0:*:*:*:*:*:*:*"},
		{"Aurora 2.11.0", "aurora", "2.11.0", "cpe:2.3:a:amazon:aurora:2.11.0:*:*:*:*:*:*:*"},
		{"Aurora wildcard version", "aurora", "", "cpe:2.3:a:amazon:aurora:*:*:*:*:*:*:*:*"},

		// Unknown
		{"Unknown with version", "unknown", "1.0.0", "cpe:2.3:a:oracle:mysql:1.0.0:*:*:*:*:*:*:*"},
		{"Unknown wildcard version", "unknown", "", "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"},

		// Empty server type
		{"Empty server empty version", "", "", "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"},
		{"Empty server with version", "", "1.0.0", "cpe:2.3:a:oracle:mysql:1.0.0:*:*:*:*:*:*:*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildMySQLCPE(tt.serverType, tt.version)
			assert.Equal(t, tt.wantCPE, cpe, "CPE mismatch")
		})
	}
}
