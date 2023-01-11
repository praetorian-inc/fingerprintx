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

package test

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/stretchr/testify/require"
)

type Testcase struct {
	// Testcase description
	Description string

	// Target port for test
	Port int

	// Target protocol for test (TCP, UDP, TCPTLS, etc.)
	Protocol plugins.Protocol

	// Function used to determine whether testcase succeeded or not
	Expected func(*plugins.Service) bool

	// Docker containers to run
	RunConfig dockertest.RunOptions
}

var dockerPool *dockertest.Pool

func RunTest(t *testing.T, tc Testcase, p plugins.Plugin) error {
	var err error
	var targetAddr string
	if dockerPool == nil {
		dockerPool, err = dockertest.NewPool("")
		if err != nil {
			log.Fatalf("could not connect to docker: %s", err)
		}
		require.NoError(t, err, "could not connect to docker")
	}
	resource, err := dockerPool.RunWithOptions(&tc.RunConfig)
	require.NoError(t, err, "could not start resource")

	// some plugins take longer to startup for the test to pass
	time.Sleep(10 * time.Second)
	if tc.Protocol == plugins.UDP {
		targetAddr = resource.GetHostPort(fmt.Sprintf("%d/udp", tc.Port))
	} else {
		targetAddr = resource.GetHostPort(fmt.Sprintf("%d/tcp", tc.Port))
	}

	fmt.Printf("trying to connect to: %s\n", targetAddr)
	err = dockerPool.Retry(func() error {
		// let the service startup
		time.Sleep(3 * time.Second)
		conn, dialErr := openConnection(targetAddr, tc.Protocol)
		if dialErr != nil {
			return dialErr
		}
		conn.Close()
		return nil
	})
	defer dockerPool.Purge(resource) //nolint:errcheck
	require.NoError(t, err, "failed to connect to test container")

	fmt.Printf("opening connection: %s\n", targetAddr)
	conn, err := openConnection(targetAddr, tc.Protocol)
	require.NoError(t, err, "failed to open connection to container")

	result, err := p.Run(conn, time.Second*2, plugins.Target{})
	require.Equal(t, true, tc.Expected(result), "failed plugin testcase")
	require.NoError(t, err, "failed to run testcase")

	return nil
}

func openConnection(target string, mode plugins.Protocol) (net.Conn, error) {
	switch mode {
	case plugins.UDP:
		return net.Dial("udp", target)
	case plugins.TCP:
		return net.Dial("tcp", target)
	case plugins.TCPTLS:
		return tls.DialWithDialer(&net.Dialer{}, "tcp", target, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec
	default:
		return nil, fmt.Errorf("invalid protocol")
	}
}
