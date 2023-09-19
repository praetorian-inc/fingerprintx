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

package ssh

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
	"github.com/praetorian-inc/fingerprintx/third_party/cryptolib/ssh"
)

type SSHPlugin struct{}

const SSH = "ssh"

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
func checkSSH(data []byte) (string, error) {
	msgLength := len(data)
	if msgLength < 4 {
		return "", &utils.InvalidResponseErrorInfo{Service: SSH, Info: "response too short"}
	}
	sshID := []byte("SSH-")
	if bytes.Equal(data[:4], sshID) {
		return string(data), nil
	}

	for _, line := range strings.Split(string(data), "\r\n") {
		if len(line) >= 4 && line[:4] == "SSH-" {
			return line, nil
		}
	}

	return "", &utils.InvalidResponseErrorInfo{Service: SSH, Info: "invalid banner prefix"}
}

func checkAlgo(data []byte) (map[string]string, error) {
	length := len(data)
	if length < 26 {
		return nil, fmt.Errorf("invalid response length")
	}
	cookie := hex.EncodeToString(data[6:22])

	kexAlgorithmsLength := int(big.NewInt(0).SetBytes(data[22:26]).Uint64())
	if length < 26+kexAlgorithmsLength {
		return nil, fmt.Errorf("invalid response length")
	}
	kexAlgos := string(data[26 : 26+kexAlgorithmsLength])

	sHKAlgoBegin := 26 + kexAlgorithmsLength
	if length < 4+sHKAlgoBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	sHKAlgoLength := int(big.NewInt(0).SetBytes(data[sHKAlgoBegin : 4+sHKAlgoBegin]).Uint64())
	if length < 4+sHKAlgoBegin+sHKAlgoLength {
		return nil, fmt.Errorf("invalid response length")
	}
	serverHostKeyAlgos := string(data[4+sHKAlgoBegin : 4+sHKAlgoBegin+sHKAlgoLength])

	encryptAlgoCToSBegin := 4 + sHKAlgoBegin + sHKAlgoLength
	if length < 4+encryptAlgoCToSBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	encryptAlgoCToSLength := int(big.NewInt(0).SetBytes(data[encryptAlgoCToSBegin : 4+encryptAlgoCToSBegin]).Uint64())
	if length < 4+encryptAlgoCToSBegin+encryptAlgoCToSLength {
		return nil, fmt.Errorf("invalid response length")
	}
	ciphersClientServer := string(data[4+encryptAlgoCToSBegin : 4+encryptAlgoCToSBegin+encryptAlgoCToSLength])

	encryptAlgoSToCBegin := 4 + encryptAlgoCToSBegin + encryptAlgoCToSLength
	if length < 4+encryptAlgoCToSBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	encryptAlgoSToCLength := int(big.NewInt(0).SetBytes(data[encryptAlgoSToCBegin : 4+encryptAlgoSToCBegin]).Uint64())
	if length < 4+encryptAlgoCToSBegin+encryptAlgoSToCLength {
		return nil, fmt.Errorf("invalid response length")
	}
	ciphersServerClient := string(data[4+encryptAlgoSToCBegin : 4+encryptAlgoSToCBegin+encryptAlgoSToCLength])

	macAlgoCToSBegin := 4 + encryptAlgoSToCBegin + encryptAlgoSToCLength
	if length < 4+macAlgoCToSBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	macAlgoCToSLength := int(big.NewInt(0).SetBytes(data[macAlgoCToSBegin : 4+macAlgoCToSBegin]).Uint64())
	if length < 4+macAlgoCToSBegin+macAlgoCToSLength {
		return nil, fmt.Errorf("invalid response length")
	}
	macClientServer := string(data[4+macAlgoCToSBegin : 4+macAlgoCToSBegin+macAlgoCToSLength])

	macAlgoSToCBegin := 4 + macAlgoCToSBegin + macAlgoCToSLength
	if length < 4+macAlgoSToCBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	macAlgoSToCLength := int(big.NewInt(0).SetBytes(data[macAlgoSToCBegin : 4+macAlgoSToCBegin]).Uint64())
	if length < 4+macAlgoSToCBegin+macAlgoCToSLength {
		return nil, fmt.Errorf("invalid response length")
	}
	macServerClient := string(data[4+macAlgoSToCBegin : 4+macAlgoSToCBegin+macAlgoSToCLength])

	compAlgoCToSBegin := 4 + macAlgoSToCBegin + macAlgoSToCLength
	if length < 4+compAlgoCToSBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	compAlgoCToSLength := int(big.NewInt(0).SetBytes(data[compAlgoCToSBegin : 4+compAlgoCToSBegin]).Uint64())
	if length < 4+compAlgoCToSBegin+compAlgoCToSLength {
		return nil, fmt.Errorf("invalid response length")
	}
	compressionClientServer := string(data[4+compAlgoCToSBegin : 4+compAlgoCToSBegin+compAlgoCToSLength])

	compAlgoSToCBegin := 4 + compAlgoCToSBegin + compAlgoCToSLength
	if length < 4+compAlgoSToCBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	compAlgoSToCLength := int(big.NewInt(0).SetBytes(data[compAlgoSToCBegin : 4+compAlgoSToCBegin]).Uint64())
	if length < 4+compAlgoSToCBegin+compAlgoSToCLength {
		return nil, fmt.Errorf("invalid response length")
	}
	compressionServerClient := string(data[4+compAlgoSToCBegin : 4+compAlgoSToCBegin+compAlgoSToCLength])

	langAlgoCToSBegin := 4 + compAlgoSToCBegin + compAlgoSToCLength
	if length < 4+langAlgoCToSBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	langAlgoCToSLength := int(big.NewInt(0).SetBytes(data[langAlgoCToSBegin : 4+langAlgoCToSBegin]).Uint64())
	if length < 4+langAlgoCToSBegin+langAlgoCToSLength {
		return nil, fmt.Errorf("invalid response length")
	}
	languagesClientServer := string(data[4+langAlgoCToSBegin : 4+langAlgoCToSBegin+langAlgoCToSLength])

	langAlgoSToCBegin := 4 + langAlgoCToSBegin + langAlgoCToSLength
	if length < 4+langAlgoCToSBegin {
		return nil, fmt.Errorf("invalid response length")
	}
	langAlgoSToCLength := int(big.NewInt(0).SetBytes(data[langAlgoSToCBegin : 4+langAlgoSToCBegin]).Uint64())
	if length < 4+langAlgoCToSBegin+langAlgoSToCLength {
		return nil, fmt.Errorf("invalid response length")
	}
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

func (p *SSHPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.Recv(conn, timeout)
	passwordAuth := false

	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	banner, err := checkSSH(response)
	if err != nil {
		return nil, err
	}

	msg := []byte("SSH-2.0-Fingerprintx-SSH2\r\n")

	response, err = utils.SendRecv(conn, msg, timeout)
	if err != nil {
		return nil, err
	}

	algo, err := checkAlgo(response)
	if err != nil {
		payload := plugins.ServiceSSH{
			Banner: banner,
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
	}

	// check auth methods
	conf := ssh.ClientConfig{}
	conf.Timeout = timeout
	conf.Auth = nil
	conf.Auth = append(conf.Auth, ssh.Password("admin"))
	conf.Auth = append(conf.Auth,
		ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range answers {
				answers[i] = "password"
			}
			return answers, nil
		}),
	)

	conf.User = "admin"
	conf.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	// use all the ciphers supported by the go crypto ssh library
	conf.KeyExchanges = append(conf.KeyExchanges,
		"diffie-hellman-group-exchange-sha256",
		"diffie-hellman-group-exchange-sha1",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group14-sha256",
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
		"curve25519-sha256@libssh.org",
		"curve25519-sha256",
	)
	conf.Ciphers = append(conf.Ciphers,
		"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"arcfour256", "arcfour128", "arcfour",
		"aes128-cbc",
		"3des-cbc",
	)

	authClient, err := ssh.Dial("tcp", target.Address.String(), &conf)

	if err != nil {
		passwordAuth = strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "keyboard-interactive")
	}

	if authClient != nil {
		authClient.Close()
	}

	sshConfig := &ssh.ClientConfig{}
	fullConf := *sshConfig
	fullConf.SetDefaults()

	c := ssh.NewTransport(conn, fullConf.Rand, true)
	t := ssh.NewHandshakeTransport(c, &fullConf.Config, msg, []byte(banner))
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
		payload := plugins.ServiceSSH{
			Banner:              banner,
			PasswordAuthEnabled: passwordAuth,
			Algo:                fmt.Sprintf("%s", algo),
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
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
		payload := plugins.ServiceSSH{
			Banner:              banner,
			PasswordAuthEnabled: passwordAuth,
			Algo:                fmt.Sprintf("%s", algo),
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
	}

	cookie, err := hex.DecodeString(algo["cookie"])
	var ret [16]byte
	copy(ret[:], cookie)

	if err != nil {
		payload := plugins.ServiceSSH{
			Banner:              banner,
			PasswordAuthEnabled: passwordAuth,
			Algo:                fmt.Sprintf("%s", algo),
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
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
		payload := plugins.ServiceSSH{
			Banner:              banner,
			PasswordAuthEnabled: passwordAuth,
			Algo:                fmt.Sprintf("%s", algo),
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
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
		payload := plugins.ServiceSSH{
			Banner:              banner,
			PasswordAuthEnabled: passwordAuth,
			Algo:                fmt.Sprintf("%s", algo),
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
	}
	hostKey, err := ssh.ParsePublicKey(result.HostKey)
	if err != nil {
		payload := plugins.ServiceSSH{
			Banner:              banner,
			PasswordAuthEnabled: passwordAuth,
			Algo:                fmt.Sprintf("%s", algo),
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
	}
	fingerprint := ssh.FingerprintSHA256(hostKey)
	base64HostKey := base64.StdEncoding.EncodeToString(result.HostKey)

	payload := plugins.ServiceSSH{
		Banner:              banner,
		PasswordAuthEnabled: passwordAuth,
		Algo:                fmt.Sprintf("%s", algo),
		HostKey:             base64HostKey,
		HostKeyType:         hostKey.Type(),
		HostKeyFingerprint:  fingerprint,
	}
	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
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
