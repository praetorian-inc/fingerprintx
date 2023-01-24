package ssh

import (
	"io"
)

func NewTransport(rwc io.ReadWriteCloser, rand io.Reader, isClient bool) *transport {
	return newTransport(rwc, rand, isClient)
}

var SupportedHostKeyAlgos = []string{
	CertAlgoRSASHA512v01, CertAlgoRSASHA256v01,
	CertAlgoRSAv01, CertAlgoDSAv01, CertAlgoECDSA256v01,
	CertAlgoECDSA384v01, CertAlgoECDSA521v01, CertAlgoED25519v01,

	KeyAlgoECDSA256, KeyAlgoECDSA384, KeyAlgoECDSA521,
	KeyAlgoRSASHA512, KeyAlgoRSASHA256,
	KeyAlgoRSA, KeyAlgoDSA,

	KeyAlgoED25519,
}

type Algorithms struct {
	Kex     string
	HostKey string
	w       directionAlgorithms
	r       directionAlgorithms
}

type HandshakeTransport struct {
	handshakeTransport
	HandshakeTransport *handshakeTransport
	Config             *Config
	SessionID          []byte
	Algorithms         *Algorithms
	ServerVersion      []byte
	ClientVersion      []byte
}

func NewHandshakeTransport(onn keyingTransport, config *Config, clientVersion, serverVersion []byte) *HandshakeTransport {
	HandshakeTransportRet := newHandshakeTransport(onn, config, clientVersion, serverVersion)
	return &HandshakeTransport{HandshakeTransport: HandshakeTransportRet,
		Config:        HandshakeTransportRet.config,
		SessionID:     HandshakeTransportRet.sessionID,
		ServerVersion: HandshakeTransportRet.serverVersion,
		ClientVersion: HandshakeTransportRet.clientVersion,
	}
}

type KexInitMsg struct {
	Cookie                  [16]byte `sshtype:"20"`
	KexAlgos                []string
	ServerHostKeyAlgos      []string
	CiphersClientServer     []string
	CiphersServerClient     []string
	MACsClientServer        []string
	MACsServerClient        []string
	CompressionClientServer []string
	CompressionServerClient []string
	LanguagesClientServer   []string
	LanguagesServerClient   []string
	FirstKexFollows         bool
	Reserved                uint32
}
type HandshakeMagics struct {
	ClientVersion, ServerVersion []byte
	ClientKexInit, ServerKexInit []byte
}

func PushPacket(t *handshakeTransport, p []byte) error {
	return t.pushPacket(p)
}

func FindAgreedAlgorithms(isClient bool, clientKexInit, serverKexInit *KexInitMsg) (algs *Algorithms, err error) {
	ClientKexInit := kexInitMsg{
		Cookie:                  clientKexInit.Cookie,
		KexAlgos:                clientKexInit.KexAlgos,
		ServerHostKeyAlgos:      clientKexInit.ServerHostKeyAlgos,
		CiphersClientServer:     clientKexInit.CiphersClientServer,
		CiphersServerClient:     clientKexInit.CiphersServerClient,
		MACsClientServer:        clientKexInit.MACsClientServer,
		MACsServerClient:        clientKexInit.MACsServerClient,
		CompressionClientServer: clientKexInit.CompressionClientServer,
		CompressionServerClient: clientKexInit.CompressionServerClient,
		LanguagesClientServer:   clientKexInit.LanguagesClientServer,
		LanguagesServerClient:   clientKexInit.LanguagesServerClient,
		FirstKexFollows:         clientKexInit.FirstKexFollows,
		Reserved:                clientKexInit.Reserved,
	}
	ServerKexInit := kexInitMsg{
		Cookie:                  serverKexInit.Cookie,
		KexAlgos:                serverKexInit.KexAlgos,
		ServerHostKeyAlgos:      serverKexInit.ServerHostKeyAlgos,
		CiphersClientServer:     serverKexInit.CiphersClientServer,
		CiphersServerClient:     serverKexInit.CiphersServerClient,
		MACsClientServer:        serverKexInit.MACsClientServer,
		MACsServerClient:        serverKexInit.MACsServerClient,
		CompressionClientServer: serverKexInit.CompressionClientServer,
		CompressionServerClient: serverKexInit.CompressionServerClient,
		LanguagesClientServer:   serverKexInit.LanguagesClientServer,
		LanguagesServerClient:   serverKexInit.LanguagesServerClient,
		FirstKexFollows:         serverKexInit.FirstKexFollows,
		Reserved:                serverKexInit.Reserved,
	}
	algorithm, err := findAgreedAlgorithms(isClient, &ClientKexInit, &ServerKexInit)
	if err != nil {
		return nil, err
	}
	algorithmRet := Algorithms{Kex: algorithm.kex, HostKey: algorithm.hostKey, w: algorithm.w, r: algorithm.r}
	return &algorithmRet, err
}

type KexAlgorithm interface {
	kexAlgorithm
}

func GetKex(kex string) KexAlgorithm {
	kexStr := kexAlgoMap[kex]
	return kexStr
}

func Clients(t *HandshakeTransport, kex KexAlgorithm, magics *HandshakeMagics) (*kexResult, error) {
	magic := handshakeMagics{clientVersion: magics.ClientVersion, clientKexInit: magics.ClientKexInit,
		serverVersion: magics.ServerVersion, serverKexInit: magics.ServerKexInit}
	result, err := kex.Client(t.HandshakeTransport.conn, t.Config.Rand, &magic)
	if err != nil {
		return nil, err
	}

	return result, nil
}
