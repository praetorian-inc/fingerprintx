package stun

import (
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/test"
)

func TestSTUN(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "stun",
			Port:        3478,
			Protocol:    plugins.UDP,
			Expected: func(res *plugins.PluginResults) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository:   "zenosmosis/docker-coturn",
				ExposedPorts: []string{"3478/udp"},
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
