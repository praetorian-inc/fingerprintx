package http

import (
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/test"
)

func TestHTTPS(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "https",
			Port:        8443,
			Protocol:    plugins.TCPTLS,
			Expected: func(res *plugins.PluginResults) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "mendhak/http-https-echo",
				Tag:        "24",
			},
		},
	}

	p := &HTTPSPlugin{}
	var config plugins.PluginConfig

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p, config)
			if err != nil {
				t.Errorf(err.Error())
			}
		})
	}
}
