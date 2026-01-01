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
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/test"
	"github.com/stretchr/testify/assert"
)

func TestFTP(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "ftp",
			Port:        21,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "panubo/vsftpd",
			},
		},
	}

	p := &FTPPlugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf(err.Error())
			}
		})
	}
}

// TestIsFTPBanner tests the core FTP detection logic with confidence scoring
func TestIsFTPBanner(t *testing.T) {
	tests := []struct {
		name       string
		banner     string
		port       uint16
		wantDetect bool
		wantConf   string
	}{
		// HIGH confidence - Port 21 + FTP keyword
		{"vsftpd on port 21", "220 (vsFTPd 2.0.1)\r\n", 21, true, "high"},
		{"ProFTPD on port 21", "220 ProFTPD 1.3.3a Server (Debian)\r\n", 21, true, "high"},
		{"Microsoft FTP on port 21", "220 Microsoft FTP Service\r\n", 21, true, "high"},
		{"Pure-FTPd on port 21", "220 Welcome to Pure-FTPd 1.0.36\r\n", 21, true, "high"},
		{"FileZilla on port 21", "220 FileZilla Server version 0.9.60\r\n", 21, true, "low"}, // No FTP keyword, falls back to port heuristic
		{"wu-ftpd on port 21", "220 FTP server (Version wu-2.6.2-5) ready.\r\n", 21, true, "high"},
		{"Generic FTP on port 21", "220 FTP Server ready\r\n", 21, true, "high"},
		{"FTP lowercase on port 21", "220 ftp server ready\r\n", 21, true, "high"},
		{"FTPD uppercase on port 21", "220 FTPD ready\r\n", 21, true, "high"},
		{"FTP service on port 21", "220 FTP service ready\r\n", 21, true, "high"},

		// MEDIUM confidence - Non-standard port + FTP keyword
		{"FTP on port 2121", "220 (vsFTPd 3.0.3)\r\n", 2121, true, "medium"},
		{"FTP on port 8021", "220 ProFTPD Server ready\r\n", 8021, true, "medium"},
		{"FTP on port 2221", "220 FTP Server ready\r\n", 2221, true, "medium"},
		{"FileZilla on port 9999", "220 FileZilla Server version 1.0.0\r\n", 9999, false, ""}, // No FTP keyword, non-standard port = reject

		// LOW confidence - Port 21 + No keyword (heuristic fallback)
		{"Generic 220 on port 21", "220 Server ready\r\n", 21, true, "low"},
		{"Numeric 220 on port 21", "220 Welcome\r\n", 21, true, "low"},
		{"Plain 220 on port 21", "220 \r\n", 21, true, "low"},

		// REJECT - PR #44 fix: SMTP on port 25
		{"Postfix SMTP on port 25", "220 smtp.example.com ESMTP Postfix\r\n", 25, false, ""},
		{"Exchange SMTP on port 25", "220 EX1.example.com Microsoft ESMTP MAIL Service\r\n", 25, false, ""},
		{"Sendmail on port 25", "220 hostname ESMTP Sendmail 8.15.2\r\n", 25, false, ""},
		{"Exim on port 25", "220 hostname ESMTP Exim 4.94.2\r\n", 25, false, ""},
		{"Generic SMTP on port 587", "220 mail.example.com ESMTP\r\n", 587, false, ""},
		{"SMTP on port 465", "220 mail.example.com ESMTP ready\r\n", 465, false, ""},

		// Edge case - FTP keyword on port 25 (legitimate if present)
		{"FTP keyword on port 25", "220 FTP server ready\r\n", 25, true, "medium"},

		// Edge cases - Empty and malformed
		{"Empty banner", "", 21, false, ""},
		{"No response code", "Hello World\r\n", 21, false, ""},
		{"Wrong response code", "500 Server error\r\n", 21, false, ""},
		{"Non-standard response", "Welcome to server\r\n", 21, false, ""},

		// Edge case - Mixed case FTP keywords
		{"FtP mixed case on port 21", "220 FtP server ready\r\n", 21, true, "high"},
		{"FTPD all caps on port 2121", "220 FTPD\r\n", 2121, true, "medium"},

		// Edge case - FTP in different positions
		{"FTP at end of banner", "220 Welcome to the FTP\r\n", 21, true, "high"},
		{"FTP Service phrase", "220 Microsoft FTP Service (Version 5.0)\r\n", 21, true, "high"},
		{"FTP server phrase", "220 Generic FTP server ready\r\n", 21, true, "high"},

		// Edge case - Similar but not FTP
		{"HTTP on port 80", "220 HTTP Server ready\r\n", 80, false, ""},
		{"SFTP (SSH FTP) on port 22", "220 SFTP ready\r\n", 22, true, "medium"}, // Contains FTP keyword
		{"TFTP on port 69", "220 TFTP ready\r\n", 69, true, "medium"},           // Contains FTP keyword
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detected, confidence := isFTPBanner(tt.banner, tt.port)
			assert.Equal(t, tt.wantDetect, detected, "Detection mismatch for: %s", tt.name)
			assert.Equal(t, tt.wantConf, confidence, "Confidence mismatch for: %s", tt.name)
		})
	}
}

// TestExtractFTPVersion tests version extraction from FTP banners
func TestExtractFTPVersion(t *testing.T) {
	tests := []struct {
		name        string
		banner      string
		wantServer  string
		wantVersion string
	}{
		// vsftpd
		{"vsftpd 2.0.1", "220 (vsFTPd 2.0.1)\r\n", "vsftpd", "2.0.1"},
		{"vsftpd 3.0.3", "220 (vsFTPd 3.0.3)\r\n", "vsftpd", "3.0.3"},
		{"vsftpd 2.2.2", "220 Welcome (vsFTPd 2.2.2)\r\n", "vsftpd", "2.2.2"},

		// ProFTPD
		{"ProFTPD 1.3.3a", "220 ProFTPD 1.3.3a Server (Debian)\r\n", "ProFTPD", "1.3.3a"},
		{"ProFTPD 1.3.5", "220 ProFTPD 1.3.5 Server\r\n", "ProFTPD", "1.3.5"},
		{"ProFTPD 1.3.7b", "220 ProFTPD 1.3.7b Server (Ubuntu)\r\n", "ProFTPD", "1.3.7b"},

		// Pure-FTPd
		{"Pure-FTPd 1.0.36", "220 Welcome to Pure-FTPd 1.0.36\r\n", "Pure-FTPd", "1.0.36"},
		{"Pure-FTPd 1.0.49", "220 Pure-FTPd 1.0.49\r\n", "Pure-FTPd", "1.0.49"},
		{"PureFTPd 1.0.42", "220 PureFTPd 1.0.42\r\n", "Pure-FTPd", "1.0.42"}, // No hyphen variant

		// FileZilla
		{"FileZilla 0.9.60", "220 FileZilla Server version 0.9.60\r\n", "FileZilla", "0.9.60"},
		{"FileZilla 1.5.0", "220 Welcome, FileZilla Server version 1.5.0\r\n", "FileZilla", "1.5.0"},

		// Microsoft IIS FTP
		{"IIS FTP 5.0", "220 Microsoft FTP Service (Version 5.0)\r\n", "Microsoft IIS", "5.0"},
		{"IIS FTP 7.5", "220 Microsoft FTP Service (Version 7.5)\r\n", "Microsoft IIS", "7.5"},
		{"IIS FTP 10.0", "220 host Microsoft FTP Service (Version 10.0)\r\n", "Microsoft IIS", "10.0"},

		// wu-ftpd
		{"wu-ftpd 2.6.2-5", "220 FTP server (Version wu-2.6.2-5) ready.\r\n", "wu-ftpd", "2.6.2-5"},
		{"wu-ftpd 2.6.1", "220 mailman FTP server (Version wu-2.6.1) ready.\r\n", "wu-ftpd", "2.6.1"},

		// Generic version pattern
		{"Generic with version", "220 FTP server (Version 1.2.3.4) ready\r\n", "Generic", "1.2.3.4"},
		{"Generic version alt", "220 FTP server (Version 4.5.6) ready\r\n", "Generic", "4.5.6"},

		// Server identified without version (fallback to server patterns)
		{"Pure-FTPd no version", "220 Welcome to Pure-FTPd [privsep] [TLS]\r\n", "Pure-FTPd", ""},
		{"vsftpd no version", "220 vsFTPd ready\r\n", "vsftpd", ""},
		{"ProFTPD no version", "220 ProFTPD Server ready\r\n", "ProFTPD", ""},
		{"FileZilla no version", "220 FileZilla Server ready\r\n", "FileZilla", ""},
		{"Microsoft FTP no version", "220 Microsoft FTP Service\r\n", "Microsoft IIS", ""},

		// No server identified
		{"No server - generic", "220 FTP Server ready\r\n", "", ""},
		{"No server - simple", "220 FTP\r\n", "", ""},
		{"Empty banner", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, version := extractFTPVersion(tt.banner)
			assert.Equal(t, tt.wantServer, server, "Server mismatch for: %s", tt.name)
			assert.Equal(t, tt.wantVersion, version, "Version mismatch for: %s", tt.name)
		})
	}
}

// TestBuildFTPCPE tests CPE generation from server type and version
func TestBuildFTPCPE(t *testing.T) {
	tests := []struct {
		name    string
		server  string
		version string
		wantCPE string
	}{
		// Valid CPE generation
		{"vsftpd", "vsftpd", "2.0.1", "cpe:2.3:a:vsftpd:vsftpd:2.0.1:*:*:*:*:*:*:*"},
		{"ProFTPD", "ProFTPD", "1.3.3a", "cpe:2.3:a:proftpd:proftpd:1.3.3a:*:*:*:*:*:*:*"},
		{"Pure-FTPd", "Pure-FTPd", "1.0.36", "cpe:2.3:a:pureftpd:pure-ftpd:1.0.36:*:*:*:*:*:*:*"},
		{"FileZilla", "FileZilla", "0.9.60", "cpe:2.3:a:filezilla-project:filezilla_server:0.9.60:*:*:*:*:*:*:*"},
		{"Microsoft IIS", "Microsoft IIS", "5.0", "cpe:2.3:a:microsoft:ftp_service:5.0:*:*:*:*:*:*:*"},

		// CPE with wildcard version - known server, unknown version (matches RMI/Wappalyzer pattern)
		{"vsftpd no version", "vsftpd", "", "cpe:2.3:a:vsftpd:vsftpd:*:*:*:*:*:*:*:*"},
		{"ProFTPD no version", "ProFTPD", "", "cpe:2.3:a:proftpd:proftpd:*:*:*:*:*:*:*:*"},
		{"Pure-FTPd no version", "Pure-FTPd", "", "cpe:2.3:a:pureftpd:pure-ftpd:*:*:*:*:*:*:*:*"},
		{"FileZilla no version", "FileZilla", "", "cpe:2.3:a:filezilla-project:filezilla_server:*:*:*:*:*:*:*:*"},
		{"Microsoft IIS no version", "Microsoft IIS", "", "cpe:2.3:a:microsoft:ftp_service:*:*:*:*:*:*:*:*"},

		// No CPE generation - empty server
		{"Empty server", "", "1.0.0", ""},

		// No CPE generation - unknown server (not in cpeVendors map)
		{"Unknown server", "UnknownFTP", "1.0.0", ""},
		{"Unknown server no version", "UnknownFTP", "", ""},

		// No CPE generation - both empty
		{"Both empty", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildFTPCPE(tt.server, tt.version)
			assert.Equal(t, tt.wantCPE, cpe, "CPE mismatch for: %s", tt.name)
		})
	}
}
