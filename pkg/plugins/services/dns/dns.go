package dns

import (
	"bytes"
	"crypto/rand"
	"net"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

const DNS = "dns"

type UDPPlugin struct{}
type TCPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&UDPPlugin{})
	plugins.RegisterPlugin(&TCPPlugin{})
}

func (p *UDPPlugin) Run(conn net.Conn, config plugins.PluginConfig) (*plugins.PluginResults, error) {
	transactionID := make([]byte, 2)
	_, err := rand.Read(transactionID)
	if err != nil {
		return nil, &utils.RandomizeError{Message: "Transaction ID"}
	}
	InitialConnectionPackage := append(transactionID, []byte{ //nolint:gocritic
		// Transaction ID
		0x01, 0x00, // Flags: 0x0100 Standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
		0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e, 0x64, 0x00, // Name: version.bind
		0x00, 0x10, // Type: TXT (Text strings) (16)
		0x00, 0x03, // Class: CH (0x0003)
	}...)

	response, err := utils.SendRecv(conn, InitialConnectionPackage, config.Timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	if bytes.Equal(transactionID[0:1], response[0:1]) {
		if len(response) > 42 {
			responseLen := response[42]
			responseTXT := string(response[43 : 43+responseLen])
			return &plugins.PluginResults{Info: map[string]any{"response": responseTXT}}, nil
		}
		return &plugins.PluginResults{}, nil
	}
	return nil, nil
}

func (p *UDPPlugin) PortPriority(i uint16) bool {
	return i == 53
}

func (p UDPPlugin) Name() string {
	return DNS
}

func (p *UDPPlugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p TCPPlugin) Run(conn net.Conn, config plugins.PluginConfig) (*plugins.PluginResults, error) {
	transactionID := make([]byte, 2)
	_, err := rand.Read(transactionID)
	if err != nil {
		return nil, &utils.RandomizeError{Message: "Transaction ID"}
	}
	InitialConnectionPackage := append(transactionID, []byte{ //nolint:gocritic
		// Transaction ID
		0x01, 0x00, // Flags: 0x0100 Standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
		0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e, 0x64, 0x00, // Name: version.bind
		0x00, 0x10, // Type: TXT (Text strings) (16)
		0x00, 0x03, // Class: CH (0x0003)
	}...)
	InitialConnectionPackage = append([]byte{0x00, 0x1e}, InitialConnectionPackage...)

	response, err := utils.SendRecv(conn, InitialConnectionPackage, config.Timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	if bytes.Equal(transactionID[0:1], response[2:3]) {
		if len(response) > 42 {
			responseLen := response[42]
			responseTXT := string(response[43 : 43+responseLen])
			return &plugins.PluginResults{Info: map[string]any{"response": responseTXT}}, nil
		}
		return &plugins.PluginResults{}, nil
	}
	return nil, nil
}

func (p TCPPlugin) PortPriority(i uint16) bool {
	return i == 53
}

func (p TCPPlugin) Name() string {
	return DNS
}

func (p *TCPPlugin) Priority() int {
	return 50
}

func (p *UDPPlugin) Priority() int {
	return 50
}

func (p TCPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}
