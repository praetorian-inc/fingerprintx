package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type RDPPlugin struct{}
type TLSPlugin struct{}

const RDP = "rdp"

func init() {
	plugins.RegisterPlugin(&RDPPlugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

// checkSignature checks if a given response matches the expected signature for
// the response
func checkSignature(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func (p *RDPPlugin) PortPriority(port uint16) bool {
	return port == 3389
}

func (p *TLSPlugin) PortPriority(port uint16) bool {
	return port == 3389
}

// getOperatingSystemSignatures returns operating system specific signatures
// for the RDP service.
func getOperatingSystemSignatures() map[string][]byte {
	Windows2000 := []byte{
		0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
	}

	WindowsServer2003 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
		0x03, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	WindowsServer2008 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	Windows7OrServer2008R2 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x09, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	WindowsServer2008R2DC := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x01, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	Windows10 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x1f, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	WindowsServer2012Or8 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x0f, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	WindowsServer2016or2019 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x1f, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00,
	}

	signatures := map[string][]byte{
		"Windows 2000":                Windows2000,
		"Windows Server 2003":         WindowsServer2003,
		"Windows Server 2008":         WindowsServer2008,
		"Windows 7 or Server 2008 R2": Windows7OrServer2008R2,
		"Windows Server 2008 R2 DC":   WindowsServer2008R2DC,
		"Windows 10":                  Windows10,
		"Windows 8 or Server 2012":    WindowsServer2012Or8,
		"Windows Server 2016 or 2019": WindowsServer2016or2019,
	}

	return signatures
}

// checkIsRDPGeneric leverages a generic RDP signature to identify if the
// target port is running the RDP service.
func checkRDP(response []byte) bool {
	GenericRDPSignature := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
	}

	signature := GenericRDPSignature
	signatureLength := len(GenericRDPSignature)

	if len(response) < signatureLength {
		return false
	}

	responseSlice := response[:signatureLength]
	tof := checkSignature(responseSlice, signature)
	return tof
}

// guessOS tries to leverage operating system specific signatures to identify
// if the target port is running a specific operating system.
func guessOS(response []byte) (bool, string) {
	signatures := getOperatingSystemSignatures()
	for fingerprint, signature := range signatures {
		signatureLength := len(signature)

		if len(response) < signatureLength {
			continue
		}

		responseSlice := response[:signatureLength]
		tof := checkSignature(responseSlice, signature)
		if tof {
			return true, fingerprint
		}
	}

	return false, ""
}

func DetectRDP(conn net.Conn, timeout time.Duration) (string, bool, error) {
	InitialConnectionPacket := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x0b,
		0x00, 0x00, 0x00,
	}

	response, err := utils.SendRecv(conn, InitialConnectionPacket, timeout)
	if err != nil {
		return "", false, err
	}
	if len(response) == 0 {
		return "", true, &utils.ServerNotEnable{}
	}

	isRDP := checkRDP(response)
	fingerprint := ""
	if isRDP {
		success, osFingerprint := guessOS(response)
		if success {
			fingerprint = osFingerprint
		}

		return fingerprint, true, nil
	}
	return "", true, &utils.InvalidResponseError{Service: RDP}
}

func DetectRDPAuth(conn net.Conn, timeout time.Duration) (map[string]any, bool, error) {
	info := make(map[string]any)

	// CredSSP protocol - NTLM authentication
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp
	// http://davenport.sourceforge.net/ntlm.html

	NegotiatePacket := []byte{
		0x30, 0x37, 0xA0, 0x03, 0x02, 0x01, 0x60, 0xA1, 0x30, 0x30, 0x2E, 0x30, 0x2C, 0xA0, 0x2A, 0x04, 0x28,
		// Signature
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00,
		// Message Type
		0x01, 0x00, 0x00, 0x00,
		// Negotiate Flags
		0xF7, 0xBA, 0xDB, 0xE2,
		// Domain Name Fields
		0x00, 0x00, // DomainNameLen
		0x00, 0x00, // DomainNameMaxLen
		0x00, 0x00, 0x00, 0x00, // DomainNameBufferOffset
		// Workstation Fields
		0x00, 0x00, // WorkstationLen
		0x00, 0x00, // WorkstationMaxLen
		0x00, 0x00, 0x00, 0x00, // WorkstationBufferOffset
		// Version
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	response, err := utils.SendRecv(conn, NegotiatePacket, timeout)
	if err != nil {
		return info, false, err
	}

	type NTLMChallenge struct {
		Signature              [8]byte
		MessageType            uint32
		TargetNameLen          uint16
		TargetNameMaxLen       uint16
		TargetNameBufferOffset uint32
		NegotiateFlags         uint32
		ServerChallenge        uint64
		Reserved               uint64
		TargetInfoLen          uint16
		TargetInfoMaxLen       uint16
		TargetInfoBufferOffset uint32
		Version                [8]byte
		// Payload (variable)
	}
	var challengeLen = 56

	challengeStartOffset := bytes.Index(response, []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0})
	if challengeStartOffset == -1 {
		return info, false, nil
	}
	if len(response) < challengeStartOffset+challengeLen {
		return info, false, nil
	}
	var responseData NTLMChallenge
	response = response[challengeStartOffset:]
	responseBuf := bytes.NewBuffer(response)
	err = binary.Read(responseBuf, binary.LittleEndian, &responseData)
	if err != nil {
		return info, false, err
	}

	// Check if valid NTLM challenge response message structure
	if responseData.MessageType != 0x00000002 ||
		responseData.Reserved != 0 ||
		!reflect.DeepEqual(responseData.Version[4:], []byte{0, 0, 0, 0xF}) {
		return info, false, nil
	}

	// Parse: Version
	type version struct {
		MajorVersion byte
		MinorVersion byte
		BuildNumber  uint16
	}
	var versionData version
	versionBuf := bytes.NewBuffer(responseData.Version[:4])
	err = binary.Read(versionBuf, binary.LittleEndian, &versionData)
	if err != nil {
		return info, true, err
	}
	info["OSVersion"] = fmt.Sprintf("%d.%d.%d", versionData.MajorVersion,
		versionData.MinorVersion,
		versionData.BuildNumber)

	// Parse: TargetName
	targetNameLen := int(responseData.TargetNameLen)
	if targetNameLen > 0 {
		startIdx := int(responseData.TargetNameBufferOffset)
		endIdx := startIdx + targetNameLen
		targetName := strings.ReplaceAll(string(response[startIdx:endIdx]), "\x00", "")
		info["TargetName"] = targetName
	}

	// Parse: TargetInfo
	AvIDMap := map[uint16]string{
		1: "NetBIOSComputerName",
		2: "NetBIOSDomainName",
		3: "FQDN", // DNS Computer Name
		4: "DNSDomainName",
		5: "DNSTreeName",
	}

	type AVPair struct {
		AvID  uint16
		AvLen uint16
		// Value (variable)
	}
	var avPairLen = 4
	targetInfoLen := int(responseData.TargetInfoLen)
	if targetInfoLen > 0 {
		startIdx := int(responseData.TargetInfoBufferOffset)
		if startIdx+targetInfoLen > len(response) {
			return info, true, fmt.Errorf("Invalid TargetInfoLen value")
		}
		var avPair AVPair
		avPairBuf := bytes.NewBuffer(response[startIdx : startIdx+avPairLen])
		err = binary.Read(avPairBuf, binary.LittleEndian, &avPair)
		if err != nil {
			return info, true, err
		}
		currIdx := startIdx
		for avPair.AvID != 0 {
			if field, exists := AvIDMap[avPair.AvID]; exists {
				value := strings.ReplaceAll(string(response[currIdx+avPairLen:currIdx+avPairLen+int(avPair.AvLen)]), "\x00", "")
				info[field] = value
			}
			currIdx += avPairLen + int(avPair.AvLen)
			if currIdx+avPairLen > startIdx+targetInfoLen {
				return info, true, fmt.Errorf("Invalid AV_PAIR list")
			}
			avPairBuf = bytes.NewBuffer(response[currIdx : currIdx+avPairLen])
			err = binary.Read(avPairBuf, binary.LittleEndian, &avPair)
			if err != nil {
				return info, true, err
			}
		}
	}

	return info, true, nil
}

func (p *RDPPlugin) Run(
	conn net.Conn,
	config plugins.PluginConfig,
) (*plugins.PluginResults, error) {
	fingerprint, check, err := DetectRDP(conn, config.Timeout)
	if check && err != nil {
		return nil, nil
	} else if check && err == nil {
		return &plugins.PluginResults{
			Info: map[string]any{"OSFingerprint": fingerprint},
		}, nil
	} else {
		return nil, err
	}
}

func (p *TLSPlugin) Run(
	conn net.Conn,
	config plugins.PluginConfig,
) (*plugins.PluginResults, error) {
	info, check, err := DetectRDPAuth(conn, config.Timeout)
	if check && err != nil {
		return nil, nil
	} else if check && err == nil {
		return &plugins.PluginResults{Info: info}, nil
	} else {
		return nil, err
	}
}

func (p *RDPPlugin) Name() string {
	return RDP
}

func (p *RDPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *TLSPlugin) Name() string {
	return RDP
}

func (p *TLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *RDPPlugin) Priority() int {
	return 89
}

func (p *TLSPlugin) Priority() int {
	return 89
}
