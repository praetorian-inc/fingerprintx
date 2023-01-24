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

package kafkaold

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"math/big"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type Plugin struct{}
type TLSPlugin struct{}

const KAFKA = "kafkaOld"
const KAFKATLS = "KafkaOldTLS"

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

func (p *Plugin) Priority() int {
	return 201
}

func (p *TLSPlugin) Priority() int {
	return 201
}

func (p *Plugin) Name() string {
	return KAFKA
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
	notReportError, err := checkMetadataQuery(conn, timeout)
	if err != nil {
		if !notReportError {
			return nil, err
		}
		return nil, nil
	}
	if !notReportError {
		return nil, nil
	}
	return plugins.CreateServiceFrom(target, plugins.ServiceKafka{}, tls, "<=0.9.0.X", plugins.TCP), nil
}

/* Helper function to generate a correlation_id */
/* Might update to be random later */
func genCorrelationID() []byte {
	cid := []byte{0x1e, 0x33, 0xf4, 0x81}
	return cid
}

/* Helper function for generating a random alphanumeric string */
func genRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	str := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", &utils.RandomizeError{Message: "KafkaRandomString"}
		}
		str[i] = charset[num.Int64()]
	}

	return string(str), nil
}

func checkMetadataQuery(conn net.Conn, timeout time.Duration) (bool, error) {
	cid := genCorrelationID()
	topicName, err := genRandomString(6)
	if err != nil {
		return false, err
	}
	metadataRequest := []byte{
		// length
		0x00, 0x00, 0x00, 0x00,
		// request_api_key
		0x00, 0x03,
		// request_api_version
		0x00, 0x00,
		// correlation_id
		cid[0], cid[1], cid[2], cid[3],
		// client_id
		0x00, 0x0d, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x63,
		0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2d, 0x35,
		// topic_count
		0x00, 0x00, 0x00, 0x01,
		// topics
		0x00, 0x06, topicName[0], topicName[1], topicName[2], topicName[3],
		topicName[4], topicName[5],
	}

	/* Correct the length field - not necessary for final script, but makes
	/* debugging easier */
	packetLength := make([]byte, 4)
	binary.BigEndian.PutUint32(packetLength, uint32(len(metadataRequest)-4))
	for i := 0; i < 4; i++ {
		metadataRequest[i] = packetLength[i]
	}

	response, err := utils.SendRecv(conn, metadataRequest, timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return true, &utils.ServerNotEnable{}
	}

	// Similar to checkApiVersions, first we test the length
	responseLength := binary.BigEndian.Uint32(response[0:4])
	expectedLength := uint32(math.Max(float64(len(response)-4), 0))
	if responseLength != expectedLength {
		return false, nil
	}

	// Next, verify correlation_id
	correlationID := response[4:8]
	for i := 0; i < 4; i++ {
		if cid[i] != correlationID[i] {
			return false, nil
		}
	}

	/* Finally, check to make sure the topic name is in the expected location.
	/* Our server's response data begins at index 8 (4 bytes for length and 4
	/* bytes for correlation_id). For metadataRequest, this is information about
	/* the available brokers, which is a variable-sized array. So we must run
	/* through the array to accurately skip over the brokers section. */
	brokerIndex := uint16(8)
	brokerCount := binary.BigEndian.Uint32(response[brokerIndex : brokerIndex+4])

	index := brokerIndex + 4
	for i := uint32(0); i < brokerCount; i++ {
		/* Each version 0 broker object looks like the following:
		/* node_id	(INT32, 4 bytes)
		/* host		(STRING, First the length N is given as an INT16. Then N bytes follow. So 2 + N bytes total)
		/* port		(INT32, 4 bytes) */
		hostLength := binary.BigEndian.Uint16(response[index+4 : index+6])
		index += 4 + 2 + hostLength + 4
	}

	topicsIndex := index

	/* Topic objects are similar to brokers, but we only requested one in our
	/* metadataRequest. So there should only be one, and the topic name is
	/* always the second field. */
	topicsIndex += 4 // for topics_count  (INT32)
	topicsIndex += 2 // for status code   (INT16)
	topicNameLength := binary.BigEndian.Uint16(response[topicsIndex : topicsIndex+2])
	topicsIndex += 2 // for string length (INT16)
	tName := string(response[topicsIndex : topicsIndex+topicNameLength])

	if tName != topicName {
		return false, nil
	}

	return true, nil
}
