package ftp

import (
	"net"
	"regexp"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

var ftpResponse = regexp.MustCompile(`^\d{3}[- ](.*)\r`)

const FTP = "ftp"

type FTPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&FTPPlugin{})
}

func (p *FTPPlugin) Run(conn net.Conn, config plugins.PluginConfig) (*plugins.PluginResults, error) {
	response, err := utils.Recv(conn, config.Timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	matches := ftpResponse.FindStringSubmatch(string(response))
	if matches == nil {
		return nil, nil
	}

	return &plugins.PluginResults{
		Info: map[string]any{
			"banner": string(response),
		}}, nil
}

func (p *FTPPlugin) PortPriority(i uint16) bool {
	return i == 21
}

func (p *FTPPlugin) Name() string {
	return FTP
}

func (p *FTPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *FTPPlugin) Priority() int {
	return 10
}
