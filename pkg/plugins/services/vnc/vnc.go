package vnc

import (
	"net"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type VNCPlugin struct{}

const VNC = "VNC"

type Info struct {
	Version string
}

// Check if the response is from a VNC server
// https://datatracker.ietf.org/doc/html/rfc6143#section-7.1
// Handshaking begins by the server sending the client a ProtocolVersion message.
//
// The ProtocolVersion message consists of 12 bytes interpreted as a
//
//	string of ASCII characters in the format "RFB xxx.yyy\n" where xxx
//	and yyy are the major and minor version numbers, left-padded with
//	zeros:
//
//	    RFB 003.008\n (hex 52 46 42 20 30 30 33 2e 30 30 38 0a)
func checkVNC(data []byte) (Info, error) {
	msgLength := len(data)
	if msgLength != 12 {
		return Info{}, &utils.InvalidResponseErrorInfo{
			Service: VNC,
			Info:    "incorrect message length",
		}
	}

	// starts with RFB
	if data[0] != 0x52 || data[1] != 0x46 || data[2] != 0x42 {
		return Info{}, &utils.InvalidResponseErrorInfo{
			Service: VNC,
			Info:    "invalid RFB preamble",
		}
	}

	// 8th element is '.' and the last is '\n'
	if data[7] != 0x2e || data[11] != 0x0a {
		return Info{}, &utils.InvalidResponseErrorInfo{
			Service: VNC,
			Info:    "missing ProtocolVersion characters",
		}
	}

	return Info{Version: string(data[4:11])}, nil
}

func init() {
	plugins.RegisterPlugin(&VNCPlugin{})
}

func (p *VNCPlugin) PortPriority(port uint16) bool {
	return port == 5900
}

func (p *VNCPlugin) Run(conn net.Conn, config plugins.PluginConfig) (*plugins.PluginResults, error) {
	response, err := utils.Recv(conn, config.Timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	info, err := checkVNC(response)
	if err != nil {
		return nil, nil
	}

	return &plugins.PluginResults{
		Info: map[string]any{"version": info.Version}}, nil
}

func (p *VNCPlugin) Name() string {
	return VNC
}

func (p *VNCPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *VNCPlugin) Priority() int {
	return 265
}
