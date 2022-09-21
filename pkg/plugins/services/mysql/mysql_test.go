package mysql

import (
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/test"
)

func TestMySQL(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "mysql",
			Port:        3306,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.PluginResults) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "mysql",
				Tag:        "5.7.39",
				Env: []string{
					"MYSQL_ROOT_PASSWORD=my-secret-pw",
				},
			},
		},
	}

	p := &MYSQLPlugin{}
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
