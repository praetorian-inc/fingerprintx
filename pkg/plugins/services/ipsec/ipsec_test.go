package ipsec

import (
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/test"
)

func TestIPSEC(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "ipsec",
			Port:        500,
			Protocol:    plugins.UDP,
			Expected: func(res *plugins.PluginResults) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "hwdsl2/ipsec-vpn-server",
				Mounts: []string{
					"ikev2-vpn-data:/etc/ipsec.d",
					"/lib/modules:/lib/modules:ro",
				},
				Privileged: true,
			},
		},
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
