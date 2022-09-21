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

func (p *RTSPPlugin) Run(conn net.Conn, config plugins.PluginConfig) (*plugins.PluginResults, error) {
	timeout := config.Timeout
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
		info := map[string]any{
			"serverInfo": response[serverValueStart : serverValueStart+serverValueEnd],
		}
		return &plugins.PluginResults{Info: info}, nil
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
