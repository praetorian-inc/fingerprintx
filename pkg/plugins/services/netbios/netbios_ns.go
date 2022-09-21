package netbios

import (
	"crypto/rand"
	"net"
	"strings"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

const NETBIOS = "netbios-ns"

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn net.Conn, config plugins.PluginConfig) (*plugins.PluginResults, error) {
	transactionID := make([]byte, 2)
	_, err := rand.Read(transactionID)
	if err != nil {
		return nil, &utils.RandomizeError{Message: "Transaction ID"}
	}
	InitialConnectionPackage := append(transactionID, []byte{ //nolint:gocritic
		// Transaction ID
		0x00, 0x10, // Flag: Broadcast
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Queries
		0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
		0x00, 0x21,
		0x00, 0x01,
	}...)

	response, err := utils.SendRecv(conn, InitialConnectionPackage, config.Timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	stringBegin := strings.Index(string(response), "\x00\x00\x00\x00\x00") + 7
	stringEnd := strings.Index(string(response), "\x20\x20\x20")
	if stringBegin == -1 || stringEnd == -1 || stringEnd < stringBegin {
		return nil, nil
	}
	info := map[string]any{"netBIOSName": string(response[stringBegin:stringEnd])}
	return &plugins.PluginResults{Info: info}, nil
}

func (p *Plugin) PortPriority(i uint16) bool {
	return i == 137
}

func (p *Plugin) Name() string {
	return NETBIOS
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 700
}
