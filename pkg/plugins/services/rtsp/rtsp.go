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

package rtsp

import (
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

const (
	RtspMagicHeader        = "RTSP/1.0"
	RtspMagicHeaderLength  = 8
	RtspCseqHeader         = "CSeq: "
	RtspCseqHeaderLength   = 6
	RtspServerHeader       = "Server: "
	RtspServerHeaderLength = 8
	RtspNewlineLength      = 2
	RTSP                   = "rtsp"
)

type RTSPPlugin struct{}

func init() {
	rand.Seed(time.Now().UnixNano())
	plugins.RegisterPlugin(&RTSPPlugin{})
}

func (p *RTSPPlugin) PortPriority(port uint16) bool {
	return port == 554
}

/*
   rtsp is a media control protocol used to control the flow of data from a real time
   data streaming protocol. rtsp itself does not transport any data. The structure of rtsp
   requests is very similar to that of http requests.

   To detect the presence of RTSP, this program sends an OPTIONS request, and then validates
   the returned header and cseq value.

   This program was tested with docker run -p 554:8554 aler9/rtsp-simple-server.
   The default port for rtsp is 554.
*/

func (p *RTSPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	cseq := strconv.Itoa(rand.Intn(10000)) //nolint:gosec

	requestString := strings.Join([]string{
		"OPTIONS rtsp://example.com RTSP/1.0\r\n",
		"Cseq: ", cseq, "\r\n",
		"\r\n",
	}, "")

	requestBytes := []byte(requestString)

	responseBytes, err := utils.SendRecv(conn, requestBytes, timeout)
	if err != nil {
		return nil, err
	}
	if len(responseBytes) == 0 {
		return nil, nil
	}
	response := string(responseBytes)

	if len(response) < RtspMagicHeaderLength {
		return nil, nil
	}
	if string(response[:RtspMagicHeaderLength]) == RtspMagicHeader {
		cseqStart := strings.Index(response, RtspCseqHeader)
		if cseqStart == -1 {
			return nil, nil
		}

		cseqValueStart := cseqStart + RtspCseqHeaderLength
		if response[cseqValueStart:cseqValueStart+len(cseq)+RtspNewlineLength] != cseq+"\r\n" {
			return nil, nil
		}

		serverStart := strings.Index(response, RtspServerHeader)
		if serverStart == -1 {
			return nil, nil
		}

		serverValueStart := serverStart + RtspServerHeaderLength
		serverValueEnd := strings.Index(response[serverValueStart:], "\r\n")
		if serverValueStart+serverValueEnd >= len(response) {
			return nil, nil
		}

		serverinfo := response[serverValueStart : serverValueStart+serverValueEnd]
		payload := plugins.ServiceRtsp{
			ServerInfo: serverinfo,
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
	}

	return nil, nil
}

func (p *RTSPPlugin) Name() string {
	return RTSP
}

func (p *RTSPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *RTSPPlugin) Priority() int {
	return 1001
}
