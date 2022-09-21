package ssh

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"strings"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
	"github.com/praetorian-inc/fingerprintx/third_party/cryptolib/ssh"
)

type SSHPlugin struct{}

const SSH = "ssh"

type Info struct {
	Info string
}

func init() {
	plugins.RegisterPlugin(&SSHPlugin{})
}

func (p *SSHPlugin) PortPriority(port uint16) bool {
	return port == 22 || port == 2222
}

// https://www.rfc-editor.org/rfc/rfc4253.html#section-4
// from the RFC, two things:
// When the connection has been established, both sides MUST send an
// identification string.  This identification string MUST be
//
//	SSH-protoversion-softwareversion SP comments CR LF
//
// The server MAY send other lines of data before sending the version
//
//	string.  Each line SHOULD be terminated by a Carriage Return and Line
//	Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be encoded
//	in ISO-10646 UTF-8 [RFC3629] (language is not specified).
func checkSSH(data []byte) (Info, error) {
	msgLength := len(data)
	if msgLength < 4 {
		return Info{}, &utils.InvalidResponseErrorInfo{Service: SSH, Info: "response too short"}
	}
	sshID := []byte("SSH-")
	if bytes.Equal(data[:4], sshID) {
		return Info{Info: string(data)}, nil
	}

	for _, line := range strings.Split(string(data), "\r\n") {
		if len(line) >= 4 && line[:4] == "SSH-" {
			return Info{Info: line}, nil
		}
	}

	return Info{}, &utils.InvalidResponseErrorInfo{Service: SSH, Info: "invalid banner prefix"}
}

func checkAlgo(data []byte) (map[string]string, error) {
	cookie := hex.EncodeToString(data[6:22])

	kexAlgorithmsLength := int(big.NewInt(0).SetBytes(data[22:26]).Uint64())
	kexAlgos := string(data[26 : 26+kexAlgorithmsLength])

	sHKAlgoBegin := 26 + kexAlgorithmsLength
	sHKAlgoLength := int(big.NewInt(0).SetBytes(data[sHKAlgoBegin : 4+sHKAlgoBegin]).Uint64())
	serverHostKeyAlgos := string(data[4+sHKAlgoBegin : 4+sHKAlgoBegin+sHKAlgoLength])

	encryptAlgoCToSBegin := 4 + sHKAlgoBegin + sHKAlgoLength
	encryptAlgoCToSLength := int(big.NewInt(0).SetBytes(data[encryptAlgoCToSBegin : 4+encryptAlgoCToSBegin]).Uint64())
	ciphersClientServer := string(data[4+encryptAlgoCToSBegin : 4+encryptAlgoCToSBegin+encryptAlgoCToSLength])

	encryptAlgoSToCBegin := 4 + encryptAlgoCToSBegin + encryptAlgoCToSLength
	encryptAlgoSToCLength := int(big.NewInt(0).SetBytes(data[encryptAlgoSToCBegin : 4+encryptAlgoSToCBegin]).Uint64())
	ciphersServerClient := string(data[4+encryptAlgoSToCBegin : 4+encryptAlgoSToCBegin+encryptAlgoSToCLength])

	macAlgoCToSBegin := 4 + encryptAlgoSToCBegin + encryptAlgoSToCLength
	macAlgoCToSLength := int(big.NewInt(0).SetBytes(data[macAlgoCToSBegin : 4+macAlgoCToSBegin]).Uint64())
	macClientServer := string(data[4+macAlgoCToSBegin : 4+macAlgoCToSBegin+macAlgoCToSLength])

	macAlgoSToCBegin := 4 + macAlgoCToSBegin + macAlgoCToSLength
	macAlgoSToCLength := int(big.NewInt(0).SetBytes(data[macAlgoSToCBegin : 4+macAlgoSToCBegin]).Uint64())
	macServerClient := string(data[4+macAlgoSToCBegin : 4+macAlgoSToCBegin+macAlgoSToCLength])

	compAlgoCToSBegin := 4 + macAlgoSToCBegin + macAlgoSToCLength
	compAlgoCToSLength := int(big.NewInt(0).SetBytes(data[compAlgoCToSBegin : 4+compAlgoCToSBegin]).Uint64())
	compressionClientServer := string(data[4+compAlgoCToSBegin : 4+compAlgoCToSBegin+compAlgoCToSLength])

	compAlgoSToCBegin := 4 + compAlgoCToSBegin + compAlgoCToSLength
	compAlgoSToCLength := int(big.NewInt(0).SetBytes(data[compAlgoSToCBegin : 4+compAlgoSToCBegin]).Uint64())
	compressionServerClient := string(data[4+compAlgoSToCBegin : 4+compAlgoSToCBegin+compAlgoSToCLength])

	langAlgoCToSBegin := 4 + compAlgoSToCBegin + compAlgoSToCLength
	langAlgoCToSLength := int(big.NewInt(0).SetBytes(data[langAlgoCToSBegin : 4+langAlgoCToSBegin]).Uint64())
	languagesClientServer := string(data[4+langAlgoCToSBegin : 4+langAlgoCToSBegin+langAlgoCToSLength])

	langAlgoSToCBegin := 4 + langAlgoCToSBegin + langAlgoCToSLength
	langAlgoSToCLength := int(big.NewInt(0).SetBytes(data[langAlgoSToCBegin : 4+langAlgoSToCBegin]).Uint64())
	languagesServerClient := string(data[4+langAlgoSToCBegin : 4+langAlgoSToCBegin+langAlgoSToCLength])

	info := map[string]string{
		"Cookie":                  cookie,
		"KexAlgos":                kexAlgos,
		"ServerHostKeyAlgos":      serverHostKeyAlgos,
		"CiphersClientServer":     ciphersClientServer,
		"CiphersServerClient":     ciphersServerClient,
		"MACsClientServer":        macClientServer,
		"MACsServerClient":        macServerClient,
		"CompressionClientServer": compressionClientServer,
		"CompressionServerClient": compressionServerClient,
		"LanguagesClientServer":   languagesClientServer,
		"LanguagesServerClient":   languagesServerClient,
	}

	return info, nil
}

func (p *SSHPlugin) Run(conn net.Conn, config plugins.PluginConfig) (*plugins.PluginResults, error) {
	response, err := utils.Recv(conn, config.Timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	banner, err := checkSSH(response)
	if err != nil {
		return nil, nil
	}

	msg := []byte("SSH-2.0-Fingerprintx-SSH2\r\n")

	response, err = utils.SendRecv(conn, msg, config.Timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}
	algo, err := checkAlgo(response)
	if err != nil {
		return &plugins.PluginResults{
			Info: map[string]any{"Banner": banner.Info}}, nil
	}

	sshConfig := &ssh.ClientConfig{}
	fullConf := *sshConfig
	fullConf.SetDefaults()

	c := ssh.NewTransport(conn, fullConf.Rand, true)
	t := ssh.NewHandshakeTransport(c, &fullConf.Config, msg, []byte(banner.Info))
	sendMsg := ssh.KexInitMsg{
		KexAlgos:                t.Config.KeyExchanges,
		CiphersClientServer:     t.Config.Ciphers,
		CiphersServerClient:     t.Config.Ciphers,
		MACsClientServer:        t.Config.MACs,
		MACsServerClient:        t.Config.MACs,
		ServerHostKeyAlgos:      ssh.SupportedHostKeyAlgos,
		CompressionClientServer: []string{"none"},
		CompressionServerClient: []string{"none"},
	}
	_, err = io.ReadFull(rand.Reader, sendMsg.Cookie[:])
	if err != nil {
		return &plugins.PluginResults{
			Info: map[string]any{"banner": banner.Info, "algorithm": algo}}, nil
	}
	if firstKeyExchange := t.SessionID == nil; firstKeyExchange {
		sendMsg.KexAlgos = make([]string, 0, len(t.Config.KeyExchanges)+1)
		sendMsg.KexAlgos = append(sendMsg.KexAlgos, t.Config.KeyExchanges...)
		sendMsg.KexAlgos = append(sendMsg.KexAlgos, "ext-info-c")
	}
	packet := ssh.Marshal(sendMsg)
	packetCopy := make([]byte, len(packet))
	copy(packetCopy, packet)

	err = ssh.PushPacket(t.HandshakeTransport, packetCopy)
	if err != nil {
		return &plugins.PluginResults{
			Info: map[string]any{"banner": banner.Info, "algorithm": algo}}, nil
	}

	cookie, err := hex.DecodeString(algo["cookie"])
	var ret [16]byte
	copy(ret[:], cookie)

	if err != nil {
		return &plugins.PluginResults{
			Info: map[string]any{"Banner": banner.Info, "Algorithm": algo}}, nil
	}
	otherInit := &ssh.KexInitMsg{
		KexAlgos:                strings.Split(algo["KexAlgos"], ","),
		Cookie:                  ret,
		ServerHostKeyAlgos:      strings.Split(algo["ServerHostKeyAlgos"], ","),
		CiphersClientServer:     strings.Split(algo["CiphersClientServer"], ","),
		CiphersServerClient:     strings.Split(algo["CiphersServerClient"], ","),
		MACsClientServer:        strings.Split(algo["MACsClientServer"], ","),
		MACsServerClient:        strings.Split(algo["MACsServerClient"], ","),
		CompressionClientServer: strings.Split(algo["CompressionClientServer"], ","),
		CompressionServerClient: strings.Split(algo["CompressionServerClient"], ","),
		FirstKexFollows:         false,
		Reserved:                0,
	}

	t.Algorithms, err = ssh.FindAgreedAlgorithms(false, &sendMsg, otherInit)
	if err != nil {
		return &plugins.PluginResults{
			Info: map[string]any{"banner": banner.Info, "algorithm": algo}}, nil
	}
	magics := ssh.HandshakeMagics{
		ClientVersion: t.ClientVersion,
		ServerVersion: t.ServerVersion,
		ClientKexInit: packet,
		ServerKexInit: response[5 : len(response)-10],
	}

	kex := ssh.GetKex(t.Algorithms.Kex)

	result, err := ssh.Clients(t, kex, &magics)
	if err != nil {
		return &plugins.PluginResults{
			Info: map[string]any{"banner": banner.Info, "algorithm": algo}}, nil
	}
	hostKey, err := ssh.ParsePublicKey(result.HostKey)
	if err != nil {
		return &plugins.PluginResults{
			Info: map[string]any{"banner": banner.Info, "algorithm": algo}}, nil
	}
	fingerprint := ssh.FingerprintSHA256(hostKey)
	base64HostKey := base64.StdEncoding.EncodeToString(result.HostKey)

	hostKeyData := map[string]string{
		"base64Encoded": base64HostKey,
		"type":          hostKey.Type(),
		"fingerprint":   fingerprint,
	}

	return &plugins.PluginResults{
		Info: map[string]any{
			"banner":    banner.Info,
			"algorithm": algo,
			"hostKey":   hostKeyData,
		}}, nil
}

func (p *SSHPlugin) Name() string {
	return SSH
}

func (p *SSHPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *SSHPlugin) Priority() int {
	return 2
}
