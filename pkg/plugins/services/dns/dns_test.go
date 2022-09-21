package dns

import (
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/test"
)

func TestDNS(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "dns",
			Port:        53,
			Protocol:    plugins.UDP,
			Expected: func(res *plugins.PluginResults) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "ruudud/devdns",
				Mounts:     []string{"/var/run/docker.sock:/var/run/docker.sock:ro"},
				Privileged: true,
			},
		},
	}

	var p *UDPPlugin
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
