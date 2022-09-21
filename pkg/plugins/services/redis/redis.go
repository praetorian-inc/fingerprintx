package redis

import (
	"bytes"
	"net"
	"strconv"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type REDISPlugin struct{}

type Info struct {
	AuthRequired bool
}

const REDIS = "redis"

// Check if the response is from a Redis server
// returns an error if it's not validated as a Redis server
// and a Info struct with AuthRequired if it is
func checkRedis(data []byte) (Info, error) {
	// a valid pong response will be the 7 bytes [+PONG(CR)(NL)]
	pong := [7]byte{0x2b, 0x50, 0x4f, 0x4e, 0x47, 0x0d, 0x0a}
	// an auth error will start with the 7 bytes: [-NOAUTH]
	noauth := [7]byte{0x2d, 0x4e, 0x4f, 0x41, 0x55, 0x54, 0x48}

	msgLength := len(data)
	if msgLength < 7 {
		return Info{}, &utils.InvalidResponseErrorInfo{
			Service: REDIS,
			Info:    "too short of a response",
		}
	}

	if msgLength == 7 {
		if bytes.Equal(data, pong[:]) {
			// Valid PONG response means redis server and no auth
			return Info{AuthRequired: false}, nil
		}
		return Info{}, &utils.InvalidResponseErrorInfo{
			Service: REDIS,
			Info:    "invalid PONG response",
		}
	}
	if !bytes.Equal(data[:7], noauth[:]) {
		return Info{}, &utils.InvalidResponseErrorInfo{
			Service: REDIS,
			Info:    "invalid Error response",
		}
	}

	return Info{AuthRequired: true}, nil
}

func init() {
	plugins.RegisterPlugin(&REDISPlugin{})
}

func (p *REDISPlugin) PortPriority(port uint16) bool {
	return port == 6379
}

func (p *REDISPlugin) Run(conn net.Conn, config plugins.PluginConfig) (*plugins.PluginResults, error) {
	timeout := config.Timeout
	//https://redis.io/commands/ping/
	// PING is a supported command since 1.0.0
	// [*1(CR)(NL)$4(CR)(NL)PING(CR)(NL)]
	ping := []byte{
		0x2a,
		0x31,
		0x0d,
		0x0a,
		0x24,
		0x34,
		0x0d,
		0x0a,
		0x50,
		0x49,
		0x4e,
		0x47,
		0x0d,
		0x0a,
	}

	response, err := utils.SendRecv(conn, ping, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	result, err := checkRedis(response)
	if err != nil {
		return nil, nil
	}
	info := map[string]any{
		"authRequired": strconv.FormatBool(result.AuthRequired),
	}
	return &plugins.PluginResults{Info: info}, nil
}

func (p *REDISPlugin) Name() string {
	return REDIS
}

func (p *REDISPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *REDISPlugin) Priority() int {
	return 413
}
