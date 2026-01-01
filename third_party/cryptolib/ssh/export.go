package ssh

import (
	"io"
)

// NewTransport creates a new SSH transport layer.
func NewTransport(rwc io.ReadWriteCloser, rand io.Reader, isClient bool) *transport {
	return newTransport(rwc, rand, isClient)
}

// SupportedHostKeyAlgos lists all host key algorithms supported by this library.
var SupportedHostKeyAlgos = []string{
	CertAlgoRSASHA512v01, CertAlgoRSASHA256v01,
	CertAlgoRSAv01, CertAlgoDSAv01, CertAlgoECDSA256v01,
	CertAlgoECDSA384v01, CertAlgoECDSA521v01, CertAlgoED25519v01,

	KeyAlgoECDSA256, KeyAlgoECDSA384, KeyAlgoECDSA521,
	KeyAlgoRSASHA512, KeyAlgoRSASHA256,
	KeyAlgoRSA, KeyAlgoDSA,

	KeyAlgoED25519,
}

// NegotiatedAlgos wraps the negotiated algorithms result for external use.
// Maps to the internal NegotiatedAlgorithms type.
type NegotiatedAlgos struct {
	Kex     string
	HostKey string
	w       DirectionAlgorithms
	r       DirectionAlgorithms
}

// HandshakeTransport wraps the internal handshake transport for external use.
type HandshakeTransport struct {
	handshakeTransport
	HandshakeTransport *handshakeTransport
	Config             *Config
	SessionID          []byte
	Algorithms         *NegotiatedAlgos
	ServerVersion      []byte
	ClientVersion      []byte
}

// NewHandshakeTransport creates a new handshake transport layer.
func NewHandshakeTransport(conn keyingTransport, config *Config, clientVersion, serverVersion []byte) *HandshakeTransport {
	ht := newHandshakeTransport(conn, config, clientVersion, serverVersion)
	return &HandshakeTransport{
		HandshakeTransport: ht,
		Config:             ht.config,
		SessionID:          ht.sessionID,
		ServerVersion:      ht.serverVersion,
		ClientVersion:      ht.clientVersion,
	}
}

// KexInitMsg represents a key exchange initialization message.
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

// HandshakeMagics contains the magic bytes exchanged during handshake.
type HandshakeMagics struct {
	ClientVersion, ServerVersion []byte
	ClientKexInit, ServerKexInit []byte
}

// PushPacket pushes a packet to the handshake transport.
func PushPacket(t *handshakeTransport, p []byte) error {
	return t.pushPacket(p)
}

// FindAgreedAlgorithms finds mutually supported algorithms between client and server.
func FindAgreedAlgorithms(isClient bool, clientKexInit, serverKexInit *KexInitMsg) (algs *NegotiatedAlgos, err error) {
	clientInit := kexInitMsg{
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
	serverInit := kexInitMsg{
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

	negotiated, err := findAgreedAlgorithms(isClient, &clientInit, &serverInit)
	if err != nil {
		return nil, err
	}

	// Map NegotiatedAlgorithms to our NegotiatedAlgos type
	result := NegotiatedAlgos{
		Kex:     negotiated.KeyExchange,
		HostKey: negotiated.HostKey,
		w:       negotiated.Write,
		r:       negotiated.Read,
	}
	return &result, nil
}

// KexAlgorithm is an interface for key exchange algorithms.
type KexAlgorithm interface {
	kexAlgorithm
}

// GetKex returns the key exchange algorithm for the given name.
func GetKex(kex string) KexAlgorithm {
	return kexAlgoMap[kex]
}

// Clients performs the client side of key exchange.
func Clients(t *HandshakeTransport, kex KexAlgorithm, magics *HandshakeMagics) (*kexResult, error) {
	magic := handshakeMagics{
		clientVersion: magics.ClientVersion,
		clientKexInit: magics.ClientKexInit,
		serverVersion: magics.ServerVersion,
		serverKexInit: magics.ServerKexInit,
	}
	result, err := kex.Client(t.HandshakeTransport.conn, t.Config.Rand, &magic)
	if err != nil {
		return nil, err
	}
	return result, nil
}
