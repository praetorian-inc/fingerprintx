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

func TestFTPBannerRegex(t *testing.T) {
	// Regex ftpResponse to match FTP banners but exclude SMTP

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Should MATCH - FTP banners
		{"FTP Welcome", "220 Welcome to FTP Server\r", true},
		{"ProFTPD Banner", "220-ProFTPD Server ready\r", true},
		{"FTP Too Many Connections", "421 Too many FTP connections\r", true},
		{"FileZilla Banner", "220 FileZilla Server ready\r", true},
		{"vsftpd Banner", "220 vsftpd 3.0.3 ready\r", true},
		{"vsftpd Parentheses", "220 (vsFTPd 3.0.3)\r", true},

		{"Pure-FTPd Banner", "220---------- Welcome to Pure-FTPd ----------\r", true},
		{"Microsoft FTP", "220 Microsoft FTP Service\r", true},
		{"Generic FTP Ready", "220 FTP server ready\r", true},
		{"FTP File Transfer", "220 File Transfer Protocol ready\r", true},
		{"FTP Connection Limit", "421 Connection limit reached\r", true},
		{"IIS FTP", "220 IIS FTP Server ready\r", true},
		{"Serv-U FTP", "220 Serv-U FTP Server ready\r", true},

		// Should NOT MATCH - SMTP banners
		{"ESMTP Banner", "220 mail.example.com ESMTP ready\r", false},
		{"SMTP Service Unavailable", "421 4.3.2 Service not available, SMTP server busy\r", false},
		{"Postfix Banner", "220 postfix ready\r", false},
		{"Gmail SMTP", "220 smtp.gmail.com ESMTP ready\r", false},
		{"Sendmail Banner", "220 sendmail 8.15.2 ready\r", false},
		{"Exim Banner", "220 exim-4.94.2 ready\r", false},
		{"Qmail Banner", "220 qmail ready\r", false},
		{"Dovecot Banner", "220 dovecot ready\r", false},
		{"Courier Banner", "220 courier-mta ready\r", false},
		{"Mail Server", "220 mail.domain.com ready\r", false},
		{"SMTP Caps", "250 SMTP server ready\r", false},
		{"ESMTP Extended", "220 Extended SMTP ready\r", false},

		// Edge cases
		{"No Carriage Return", "220 FTP Server ready", false}, // Missing \r
		{"Wrong Code Format", "22 FTP Server ready\r", false}, // Not 3 digits
		{"No Separator", "220FTP Server ready\r", false},      // Missing space/hyphen
		{"Empty Content", "220 \r", true},                     // Valid but empty
		{"Mixed Case SMTP", "220 Smtp Server ready\r", false}, // Should catch lowercase
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isFTPBanner(tt.input, 25)
			if result != tt.expected {
				t.Errorf("Input %q: expected %v, got %v", tt.input, tt.expected, result)
			}
		})
	}
}
