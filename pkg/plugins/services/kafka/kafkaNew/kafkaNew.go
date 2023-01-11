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

package kafkanew

import (
	"encoding/binary"
	"math"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type Plugin struct{}
type TLSPlugin struct{}

const KAFKA = "kafkaNew"
const KAFKATLS = "KafkaNewTLS"

func init() {
	plugins.RegisterPlugin(&Plugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	result, err := Run(conn, false, timeout, target)
	return result, err
}

func (p *Plugin) PortPriority(i uint16) bool {
	return i == 9092
}

func (p *Plugin) Name() string {
	return KAFKA
}

func (p *Plugin) Priority() int {
	return 200
}

func (p *TLSPlugin) Priority() int {
	return 200
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	result, err := Run(conn, true, timeout, target)
	return result, err
}

func (p *TLSPlugin) PortPriority(i uint16) bool {
	return i == 9093
}

func (p *TLSPlugin) Name() string {
	return KAFKATLS
}

func (p *TLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

/*
Run Kafka scanner plugins.

Primary Sources:
  - https://kafka.apache.org/protocol.html (Gold mine)
  - https://kafka.apache.org/documentation.html
  - https://kafka.apache.org/downloads

Methodology:
Scanning for Kafka is a bit tricky, so I've outlined my methodology here. Kafka
is harder to detect reliably for a few reasons:
  - Kafka brokers may optionally require authentication via SASL before most
    commands can be issued.
  - There are many different versions of Kafka, and most API calls work slightly
    different on each versions (especially for pre-0.9.0.X releases)

Fortunately, Kafka versions 0.10.0.0 and later support the ApiVersions request,
which can be sent by an unauthenticated user to check which API requests are
supported by the broker. Also versions prior to 0.9.0.0 do not offer any form of
authentication. And, all versions of Kafka are compatible with any older client.
This means that:
 1. If Kafka version 0.10.0.0 or higher is running, we can confirm with the
    ApiVersions request regardless of if authentication is required This
    includes any version of Kafka released since May, 2016.
 2. If Kafka version 0.8.0.X or earlier is running, we can confirm with a simple
    data query using API version 0.
 3. If Kafka version 0.9.0.X is running and does not require authentication, we
    can also confirm with a simple v0 data query.

I'm not sure if Kafka brokers running version 0.9.0.X that do require
authentication will be detected by any of the above methods. It's possible that
strategy 3 will still work in this situation, but I was not able to confirm due
to the difficulty of setting up a testing environment for an older version.
*/
func Run(conn net.Conn, tls bool, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	/* Initiate first TCP connection with target. If the target is running an
	/* older version of Kafka, the connection will be terminated after sending
	/* ApiVersions, and we will need to make a new one. */
	/* Make first notReportError - this will catch any broker running Kafka 0.10.0.0 or
	/* later. */
	notReportError, err := checkAPIVersions(conn, timeout)
	if err != nil {
		if !notReportError {
			return nil, err
		}
		return nil, nil
	}
	if !notReportError {
		return nil, nil
	}

	return plugins.CreateServiceFrom(target, plugins.ServiceKafka{}, tls, ">=0.10.0.0", plugins.TCP), nil
}

/* Helper function to generate a correlation_id */
/* Might update to be random later */
func genCorrelationID() []byte {
	cid := []byte{0x1e, 0x33, 0xf4, 0x81}
	return cid
}

/*
	checkApiVersions - sends an ApiVersions request and validates the output.

/*
/* Note that if the broker does not support ApiVersions, it might terminate the
/* TCP connection (source: https://kafka.apache.org/protocol.html#api_versions).
/*
/* The function sends an ApiVersions request because this is widely supported,
/* and does not require authentication. All Kafka responses start with the
/* packet length followed by the "correlation ID", which is a value specified by
/* the client and included in their request. So we check to make sure the first
/* four bytes (length) are equivalent to the size of the response data and the
/* next four bytes (correlation ID) match the ID included in the request.
/* Further reading: https://kafka.apache.org/protocol.html#protocol_messages
*/
func checkAPIVersions(conn net.Conn, timeout time.Duration) (bool, error) {
	cid := genCorrelationID()
	apiVersionsRequest := []byte{
		/* length */
		0x00, 0x00, 0x00, 0x43,
		/* request_api_key */
		0x00, 0x12,
		/* request_api_version */
		0x00, 0x00,
		/* correlation_id */
		cid[0], cid[1], cid[2], cid[3],
		/* client_id */
		0x00, 0x1f, 0x63, 0x6f, 0x6e, 0x73, 0x75, 0x6d,
		0x65, 0x72, 0x2d, 0x4f, 0x66, 0x66, 0x73, 0x65,
		0x74, 0x20, 0x45, 0x78, 0x70, 0x6c, 0x6f, 0x72,
		0x65, 0x72, 0x20, 0x32, 0x2e, 0x32, 0x2d, 0x31,
		0x38,
		/* TAG_BUFFER */
		0x00,
		/* client_software_name */
		0x12, 0x61, 0x70, 0x61, 0x63, 0x68, 0x65, 0x2d,
		0x6b, 0x61, 0x66, 0x6b, 0x61, 0x2d, 0x6a, 0x61,
		0x76, 0x61,
		/* client_software_version */
		0x06, 0x32, 0x2e, 0x34, 0x2e, 0x30,
		/* _tagged_fields */
		0x00,
	}

	response, err := utils.SendRecv(conn, apiVersionsRequest, timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return true, &utils.ServerNotEnable{}
	}

	responseLength := binary.BigEndian.Uint32(response[0:4])
	expectedLength := uint32(math.Max(float64(len(response)-4), 0))
	correlationID := response[4:8]

	// First, check to see if the response length makes sense
	if responseLength != expectedLength {
		return false, nil
	}

	// Next, make sure the correlation IDs match up
	for i := 0; i < len(cid); i++ {
		if cid[i] != correlationID[i] {
			return false, nil
		}
	}

	return true, nil
}
