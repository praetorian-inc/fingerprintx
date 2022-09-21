package oracledb

import (
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/test"
)

func TestOracleDB(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "oracledb",
			Port:        1521,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.PluginResults) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "babim/oracledatabase",
				Tag:        "11.2.0.4",
			},
		},
	}

	p := &ORACLEPlugin{}
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
