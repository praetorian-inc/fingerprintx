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

package http

import (
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/test"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

func TestHTTPS(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "https",
			Port:        8443,
			Protocol:    plugins.TCPTLS,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "mendhak/http-https-echo",
				Tag:        "24",
			},
		},
	}

	p := HTTPSPlugin{}
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		panic("unable to initialize wappalyzer library")
	}
	p.analyzer = wappalyzerClient

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, &p)
			if err != nil {
				t.Errorf(err.Error())
			}
		})
	}
}
