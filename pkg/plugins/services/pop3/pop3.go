package pop3

import (
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type POP3Plugin struct{} // POP3
type TLSPlugin struct{}  // POP3S

const POP3 = "pop3"
const POP3S = "pop3s"

func init() {
	plugins.RegisterPlugin(&POP3Plugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

func (p *POP3Plugin) PortPriority(port uint16) bool {
	return port == 110
}

func DetectPOP3(conn net.Conn, timeout time.Duration, tls bool) (string, bool, error) {
	// read initial response from server
	initialResponse, err := utils.Recv(conn, timeout)
	if err != nil {
		return "", false, err
	}
	if len(initialResponse) == 0 {
		return "", true, &utils.ServerNotEnable{}
	}

	// send a bogus command and read error response
	errResponse, err := utils.SendRecv(conn, []byte("Not a command \r\n"), timeout)
	if err != nil {
		return "", false, err
	}
	if len(errResponse) == 0 {
		return "", true, &utils.ServerNotEnable{}
	}

	isPOP3 := false
	if strings.HasPrefix(string(initialResponse), "+OK") &&
		strings.HasPrefix(string(errResponse), "-ERR") {
		isPOP3 = true
	}

	if !isPOP3 {
		// no ? :(
		if tls {
			return "", true, &utils.InvalidResponseErrorInfo{
				Service: POP3S,
				Info:    "did not get expected banner for POP3S",
			}
		}
		return "", true, &utils.InvalidResponseErrorInfo{
			Service: POP3,
			Info:    "did not get expected banner for POP3",
		}
	}

	return string(initialResponse[4:]), true, nil
}

func (p *POP3Plugin) Run(conn net.Conn, config plugins.PluginConfig) (*plugins.PluginResults, error) {
	result, check, err := DetectPOP3(conn, config.Timeout, false)

	if check && err != nil { // service is not running POP3
		return nil, nil
	} else if !check && err != nil { // plugin error
		return nil, err
	}

	// service is running POP3
	return &plugins.PluginResults{Info: map[string]any{"banner": result}}, nil
}

func (p *TLSPlugin) PortPriority(port uint16) bool {
	return port == 995
}

func (p *TLSPlugin) Run(
	conn net.Conn,
	config plugins.PluginConfig,
) (*plugins.PluginResults, error) {
	result, check, err := DetectPOP3(conn, config.Timeout, true)

	if check && err != nil { // service is not running POP3S
		return nil, nil
	} else if !check && err != nil { // plugin error
		return nil, err
	}

	// service is running POP3S
	return &plugins.PluginResults{Info: map[string]any{"banner": result}}, nil
}

func (p *POP3Plugin) Name() string {
	return POP3
}

func (p *POP3Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *TLSPlugin) Name() string {
	return POP3S
}

func (p *TLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *POP3Plugin) Priority() int {
	return 120
}

func (p *TLSPlugin) Priority() int {
	return 122
}
