package openvpn

import (
	"testing"

	// "github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/test"
)

func TestOpenVPN(t *testing.T) {

	// the Privileged container does not run on Github actions -- but this test passes locally
	testcases := []test.Testcase{
		// 	{
		// 		Description: "openvpn",
		// 		Port:        1194,
		// 		Protocol:    plugins.UDP,
		// 		Expected: func(res *plugins.PluginResults) bool {
		// 			return res != nil
		// 		},
		// 		RunConfig: dockertest.RunOptions{
		// 			Repository: "jpetazzo/dockvpn",
		// 			Privileged: true,
		// 		},
		// 	},
	}

	var p *Plugin
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
