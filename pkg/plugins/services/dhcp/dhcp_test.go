package dhcp

import (
	// "os"
	"testing"

	// "github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/test"
)

func TestDHCP(t *testing.T) {
	// cwd, err := os.Getwd()
	// if err != nil {
	// 	t.Fatalf("failed to get current directory")
	// }
	// TODO more work is required to get this test working locally
	testcases := []test.Testcase{
		// {
		// 	Description: "dhcp",
		// 	Port:        67,
		// 	Protocol:    plugins.UDP,
		// 	Expected: func(res *plugins.PluginResults) bool {
		// 		return res != nil
		// 	},
		// 	RunConfig: dockertest.RunOptions{
		// 		Repository:   "wastrachan/dhcpd",
		// 		Mounts:       []string{fmt.Sprintf("%s/dhcpd.conf:/config/dhcpd.conf", cwd)},
		// 		ExposedPorts: []string{"67/udp"},
		// 	},
		// },
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
