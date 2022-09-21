package http

import (
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/test"
)

func TestHTTP(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "http",
			Port:        8080,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.PluginResults) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "mendhak/http-https-echo",
				Tag:        "24",
			},
		},
	}

	p := &HTTPPlugin{}

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
