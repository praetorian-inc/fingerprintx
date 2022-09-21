package smtp

import (
	"bytes"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type SMTPPlugin struct{}
type TLSPlugin struct{}

const SMTP = "smtp"
const SMTPS = "smtps"

type Data struct {
	Banner      string
	AuthMethods []string
}

func init() {
	plugins.RegisterPlugin(&SMTPPlugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

func (p *SMTPPlugin) PortPriority(port uint16) bool {
	return port == 25 || port == 587
}

func handleSMTPConn(response []byte) (bool, bool) {
	// Checks for an expected response on CONNECTION ESTABLISHMENT
	// RFC 5321 Section 4.3.2
	validResponses := []string{"220", "421", "500", "501", "554"}
	isSMTP := false
	isSMTPErr := false
	for i := 0; i < len(validResponses); i++ {
		if bytes.Equal(response[0:3], []byte(validResponses[i])) {
			// Received a valid response code on connection
			isSMTP = true
			if bytes.Equal(response[0:1], []byte("4")) || bytes.Equal(response[0:1], []byte("5")) {
				// Received a valid error response code on connection
				isSMTPErr = true
			}
			break
		}
	}
	return isSMTP, isSMTPErr
}

func handleSMTPHelo(response []byte) (bool, bool) {
	// Checks for an expected response from the HELO command
	// RFC 5321 Section 4.3.2
	validResponses := []string{"250", "421", "500", "501", "502", "504", "550"}
	isSMTP := false
	isSMTPErr := false
	for i := 0; i < len(validResponses); i++ {
		if bytes.Equal(response[0:3], []byte(validResponses[i])) {
			// HELO command received a valid response code
			isSMTP = true
			if bytes.Equal(response[0:1], []byte("4")) || bytes.Equal(response[0:1], []byte("5")) {
				// HELO command received a valid error response code
				isSMTPErr = true
			}
			break
		}
	}
	return isSMTP, isSMTPErr
}

func (p *TLSPlugin) PortPriority(port uint16) bool {
	return port == 465
}

func DetectSMTP(conn net.Conn, tls bool, timeout time.Duration) (Data, bool, error) {
	protocol := SMTP
	if tls {
		protocol = SMTPS
	}

	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return Data{}, false, err
	}
	if len(response) == 0 {
		return Data{}, true, &utils.ServerNotEnable{}
	}

	isSMTP, smtpError := handleSMTPConn(response)
	if !isSMTP && !smtpError {
		return Data{}, true, &utils.InvalidResponseError{Service: protocol}
	}

	banner := make([]byte, len(response))
	copy(banner, response)

	// Send the EHLO message
	smtpEhloCommand := []byte("EHLO example.com\r\n")
	response, err = utils.SendRecv(conn, smtpEhloCommand, timeout)
	if err != nil {
		return Data{}, false, err
	}
	if len(response) == 0 {
		return Data{}, true, &utils.ServerNotEnable{}
	}

	isSMTP, smtpError = handleSMTPHelo(response)
	if !isSMTP {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: protocol,
			Info:    "invalid SMTP Helo response",
		}
	}

	// a valid smtperror means it is smtp
	if smtpError {
		data := Data{
			Banner: string(banner),
		}

		return data, true, nil
	}

	if isSMTP {
		data := Data{
			Banner:      string(banner),
			AuthMethods: strings.Split(strings.ReplaceAll(string(response), "-", " "), " "),
		}

		return data, true, nil
	}

	return Data{}, true, &utils.InvalidResponseError{Service: protocol}
}

func (p *SMTPPlugin) Run(
	conn net.Conn,
	config plugins.PluginConfig,
) (*plugins.PluginResults, error) {
	data, check, err := DetectSMTP(conn, false, config.Timeout)
	if err == nil && check {
		info := map[string]any{
			"banner":      data.Banner,
			"authMethods": strings.Join(data.AuthMethods, ","),
		}
		return &plugins.PluginResults{Info: info}, nil
	} else if err != nil && check {
		return nil, nil
	}
	return nil, err
}

func (p *TLSPlugin) Run(
	conn net.Conn,
	config plugins.PluginConfig,
) (*plugins.PluginResults, error) {
	data, check, err := DetectSMTP(conn, false, config.Timeout)
	if err == nil && check {
		info := map[string]any{
			"banner":      data.Banner,
			"authMethods": strings.Join(data.AuthMethods, ","),
		}
		return &plugins.PluginResults{Info: info}, nil
	} else if err != nil && check {
		return nil, nil
	}
	return nil, err
}

func (p *SMTPPlugin) Name() string {
	return SMTP
}

func (p *SMTPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *TLSPlugin) Name() string {
	return SMTPS
}

func (p *TLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *SMTPPlugin) Priority() int {
	return 60
}

func (p *TLSPlugin) Priority() int {
	return 61
}
