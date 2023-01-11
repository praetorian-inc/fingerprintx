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

package imap

import (
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type IMAPPlugin struct{}
type TLSPlugin struct{}

const IMAP = "imap"
const IMAPS = "imaps"

func init() {
	plugins.RegisterPlugin(&IMAPPlugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

/*
	checkGreeting - verifies server greeting.

/* When a client initiates a TCP handshake with an IMAP server, the server will
/* send one of three greetings immediately following the last ACK of the
/* handshake:
/*		S: * OK <status information>
/*		S: * PREAUTH <status information>
/*		S: * BYE <status information>
*/
func checkGreeting(response []byte) bool {
	srvGreet := string(response)
	srvGreetUpper := strings.ToUpper(srvGreet)

	// As per page 85 of RFC 3501, there are 3 possible greetings
	greetings := []string{"* OK", "* PREAUTH", "* BYE"}
	for _, greeting := range greetings {
		if strings.HasPrefix(srvGreetUpper, greeting) {
			return true
		}
	}

	return false
}

/*
	checkCapability - sends CAPABILITY command and verifies response data.

/* CAPABILITY is an unauthenticated IMAP command that allows the client to view
/* what other commands are supported by the server. If an IP:port is running
/* IMAP, it will return data like so:
/* 		C: 1234 CAPABILITY\r\n
/* 		S: * CAPABILITY <list of supported features>\r\n
/* 		S: 1234 OK <status information>\r\n
*/
func checkCapability(conn net.Conn, timeout time.Duration) (bool, error) {
	/* The tag will always be reflected in the server output. Using a random-
	/* looking/nonsensical tag decreases the possibility of false positive */
	tag := "7FYWU8I4"
	msg := []byte(tag + " CAPABILITY\r\n")

	response, err := utils.SendRecv(conn, msg, timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return true, &utils.ServerNotEnable{}
	}

	/* Sometimes servers send all the data in one packet
	/* If so, parse into two strings */
	srvResponses := strings.Split(string(response), "\r\n")

	if len(srvResponses) < 2 {
		return true, &utils.InvalidResponseError{Service: IMAP}
	}

	capData := strings.ToUpper(srvResponses[0])
	status := strings.ToUpper(srvResponses[1])

	// If we only got 1 IMAP response, there is probably another on the way
	if status == "" {
		response, err := utils.Recv(conn, timeout)
		if err != nil {
			return false, err
		}
		if len(response) == 0 {
			return true, &utils.ServerNotEnable{}
		}
		status = string(response)
	}

	/* Make sure server response matches RFC 3501, pages 68 (capability) and 88
	/* (response-tagged) */
	if !strings.HasPrefix(capData, "* CAPABILITY") || !strings.HasPrefix(status, tag) {
		return true, &utils.InvalidResponseErrorInfo{Service: IMAP, Info: "missing capability info"}
	}

	// imap
	return false, nil
}

func DetectIMAP(conn net.Conn, timeout time.Duration) (string, bool, error) {
	/* Server has to specify a greeting upon completing the TCP handshake as
	/* per RFC 3501 (page 14). If we don't get a greeting, this ain't IMAP. */
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return "", false, err
	}
	if len(response) == 0 {
		return "", true, &utils.ServerNotEnable{}
	}

	if !checkGreeting(response) {
		return "", true, &utils.InvalidResponseErrorInfo{
			Service: IMAP,
			Info:    "did not receive expected imap greeting banner",
		}
	}
	check, err := checkCapability(conn, timeout)
	return string(response[5:]), check, err
}

func (p *IMAPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	result, check, err := DetectIMAP(conn, timeout)
	if err != nil && check { // service is not running IMAP
		return nil, nil
	} else if err != nil && !check { // plugin error
		return nil, err
	}

	// service is running IMAP
	payload := plugins.ServiceIMAPS{
		Banner: result,
	}
	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

func (p *IMAPPlugin) PortPriority(i uint16) bool {
	return i == 143
}

func (p *IMAPPlugin) Name() string {
	return IMAP
}

func (p *IMAPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	result, check, err := DetectIMAP(conn, timeout)
	if err != nil && check { // service is not running IMAP
		return nil, nil
	} else if err != nil && !check { // plugin error
		return nil, err
	}

	// service is running IMAPS
	payload := plugins.ServiceIMAPS{
		Banner: result,
	}
	return plugins.CreateServiceFrom(target, payload, true, "", plugins.TCP), nil
}

func (p *TLSPlugin) PortPriority(i uint16) bool {
	return i == 993
}

func (p *TLSPlugin) Name() string {
	return IMAPS
}

func (p *IMAPPlugin) Priority() int {
	return 191
}

func (p *TLSPlugin) Priority() int {
	return 190
}

func (p *TLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}
