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

package smb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type SMBPlugin struct{}

const SMB = "smb"

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5cd64522-60b3-4f3e-a157-fe66f1228052
type SMB2PacketHeader struct {
	ProtocolID    [4]byte
	StructureSize uint16
	CreditCharge  uint16
	Status        uint32 // In SMB 3.x dialect, used as ChannelSequence & Reserved fields
	Command       uint16
	CreditRequest uint16
	Flags         uint32
	NextCommand   uint32
	MessageID     uint64
	Reserved      uint32
	TreeID        uint32
	SessionID     uint64
	Signature     [16]byte
}

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5
type NegotiateResponse struct {
	SessionMsgPrefix [4]byte
	PacketHeader     SMB2PacketHeader
	// Negotiate Response
	StructureSize        uint16
	SecurityMode         uint16
	DialectRevision      uint16
	Reserved             uint16 // if DialectRevision is 0x0311, used as NegotiateContextCount field
	ServerGUID           [16]byte
	Capabilities         uint32
	MaxTransactSize      uint32
	MaxReadSize          uint32
	MaxWriteSize         uint32
	SystemTime           uint64
	ServerStartTime      uint64
	SecurityBufferOffset uint16
	SecurityBufferLength uint16
	Reserved2            uint32 // if DialectRevision is 0x0311, used as NegotiateContextOffset field
	// Variable (Buffer, Padding, NegotiateContextList, etc.)
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

func init() {
	plugins.RegisterPlugin(&SMBPlugin{})
}

func (p *SMBPlugin) PortPriority(port uint16) bool {
	return port == 445
}

func DetectSMBv2(conn net.Conn, timeout time.Duration) (*plugins.ServiceSMB, error) {
	info := plugins.ServiceSMB{}

	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5
	negotiateReqPacket := []byte{
		// NetBios Session Service
		0x00,             // Message Type
		0x00, 0x00, 0x66, // Length

		// SMBv2 Packet Header
		0xFE, 0x53, 0x4D, 0x42, // ProtocolId
		0x40, 0x00, // StructureSize
		0x00, 0x00, // CreditCharge
		0x00, 0x00, 0x00, 0x00, // ChannelSequence/Reserved/Status
		0x00, 0x00, // Command (Negotiate)
		0x00, 0x1F, // CreditRequest
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // NextCommand
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageID
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // TreeID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature (continued)

		// SMBv2 Negotiate Request
		0x24, 0x00, // StructureSize
		0x01, 0x00, // DialectCount
		0x01, 0x00, // SecurityMode (Signing Enabled)
		0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Capabilities
		0x13, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, // ClientGuid
		0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x37, // ClientGuid (continued)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientStartTime
		0x02, 0x02, // Dialects (SMB 2.0.2)
	}
	sessionPrefixLen := 4
	packetHeaderLen := 64
	minNegoResponseLen := 64

	response, err := utils.SendRecv(conn, negotiateReqPacket, timeout)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, nil
		}
		return nil, err
	}

	// Check the length of the response to see if it is lower than the minimum
	// packet size for SMB2 NEGOTIATE Response Packet
	if len(response) < sessionPrefixLen+packetHeaderLen+minNegoResponseLen {
		return nil, nil
	}

	var negotiateResponseData NegotiateResponse
	responseBuf := bytes.NewBuffer(response)
	err = binary.Read(responseBuf, binary.LittleEndian, &negotiateResponseData)
	if err != nil {
		return nil, err
	}

	if !reflect.DeepEqual(negotiateResponseData.PacketHeader.ProtocolID[:], []byte{0xFE, 'S', 'M', 'B'}) {
		return nil, nil
	}

	if negotiateResponseData.PacketHeader.StructureSize != 0x40 {
		return nil, nil
	}

	if negotiateResponseData.PacketHeader.Command != 0x0000 { // SMB2 NEGOTIATE (0x0000)
		return nil, nil
	}

	if negotiateResponseData.StructureSize != 0x41 {
		return nil, nil
	}

	signingEnabled := false
	signingRequired := false
	if negotiateResponseData.SecurityMode&1 == 1 {
		signingEnabled = true
	}
	if negotiateResponseData.SecurityMode&2 == 2 {
		signingRequired = true
	}
	info.SigningEnabled = signingEnabled
	info.SigningRequired = signingRequired

	/**
	 * At this point, we know SMBv2 is detected.
	 * Below, we try to obtain more metadata via session setup request w/ NTLM auth
	 */

	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-authsod/9a20f8ac-612a-4e0a-baab-30e922e7e1f5
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a3c2c28-d6b0-48ed-b917-a86b2ca4575f
	sessionSetupReqPacket := []byte{
		// NetBios Session Service
		0x00,             // Message Type
		0x00, 0x00, 0xA2, // Length

		// SMBv2 Packet Header
		0xFE, 0x53, 0x4D, 0x42, // ProtocolId
		0x40, 0x00, // StructureSize
		0x00, 0x00, // CreditCharge
		0x00, 0x00, 0x00, 0x00, // ChannelSequence/Reserved/Status
		0x01, 0x00, // Command (SESSION_SETUP)
		0x00, 0x20, // CreditRequest
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // NextCommand
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageID
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // TreeID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature (continued)

		// SMBv2 Session Setup Request
		0x19, 0x00, // Structure Size
		0x00,                   // Flags
		0x01,                   // SecurityMode
		0x01, 0x00, 0x00, 0x00, // Capabilities
		0x00, 0x00, 0x00, 0x00, // Channel
		0x58, 0x00, // SecurityBufferOffset
		0x4A, 0x00, // SecurityBufferLength
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PreviousSessionId
		// Security Buffer
		0x60, 0x48, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05,
		0x05, 0x02, 0xA0, 0x3E, 0x30, 0x3C, 0xA0, 0x0E,
		0x30, 0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04,
		0x01, 0x82, 0x37, 0x02, 0x02, 0x0A, 0xA2, 0x2A, 0x04, 0x28,
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

	response, err = utils.SendRecv(conn, sessionSetupReqPacket, timeout)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return &info, nil
		}
		return &info, err
	}

	challengeLen := 56
	challengeStartOffset := bytes.Index(response, []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0})
	if challengeStartOffset == -1 {
		return &info, nil
	}
	if len(response) < challengeStartOffset+challengeLen {
		return &info, nil
	}
	var sessionResponseData NTLMChallenge
	response = response[challengeStartOffset:]
	responseBuf = bytes.NewBuffer(response)
	err = binary.Read(responseBuf, binary.LittleEndian, &sessionResponseData)
	if err != nil {
		return &info, err
	}

	// Check if valid NTLM challenge response message structure
	if sessionResponseData.MessageType != 0x00000002 ||
		sessionResponseData.Reserved != 0 ||
		!reflect.DeepEqual(sessionResponseData.Version[4:], []byte{0, 0, 0, 0xF}) {
		return &info, nil
	}

	// Parse: Version
	type version struct {
		MajorVersion byte
		MinorVersion byte
		BuildNumber  uint16
	}
	var versionData version
	versionBuf := bytes.NewBuffer(sessionResponseData.Version[:4])
	err = binary.Read(versionBuf, binary.LittleEndian, &versionData)
	if err != nil {
		return &info, err
	}
	info.OSVersion = fmt.Sprintf("%d.%d.%d", versionData.MajorVersion,
		versionData.MinorVersion,
		versionData.BuildNumber)

	// Parse: TargetInfo
	AvIDMap := map[uint16]string{
		1: "netbiosComputerName",
		2: "netbiosDomainName",
		3: "dnsComputerName",
		4: "dnsDomainName",
		5: "forestName", // MsvAvDnsTreeName
	}
	type AVPair struct {
		AvID  uint16
		AvLen uint16
		// Value (variable)
	}
	var avPairLen = 4
	targetInfoLen := int(sessionResponseData.TargetInfoLen)
	if targetInfoLen > 0 {
		startIdx := int(sessionResponseData.TargetInfoBufferOffset)
		if startIdx+targetInfoLen > len(response) {
			return &info, nil
		}
		var avPair AVPair
		avPairBuf := bytes.NewBuffer(response[startIdx : startIdx+avPairLen])
		err = binary.Read(avPairBuf, binary.LittleEndian, &avPair)
		if err != nil {
			return &info, err
		}
		currIdx := startIdx
		for avPair.AvID != 0 {
			if field, exists := AvIDMap[avPair.AvID]; exists {
				value := strings.ReplaceAll(string(response[currIdx+avPairLen:currIdx+avPairLen+int(avPair.AvLen)]), "\x00", "")
				switch field {
				case "netbiosComputerName":
					info.NetBIOSComputerName = value
				case "netbiosDomainName":
					info.NetBIOSDomainName = value
				case "dnsComputerName":
					info.DNSComputerName = value
				case "dnsDomainName":
					info.DNSDomainName = value
				case "forestName": // MsvAvDnsTreeName
					info.ForestName = value
				}
			}
			currIdx += avPairLen + int(avPair.AvLen)
			if currIdx+avPairLen > startIdx+targetInfoLen {
				return &info, nil
			}
			avPairBuf = bytes.NewBuffer(response[currIdx : currIdx+avPairLen])
			err = binary.Read(avPairBuf, binary.LittleEndian, &avPair)
			if err != nil {
				return &info, nil
			}
		}
	}

	return &info, nil
}

func (p *SMBPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	info, err := DetectSMBv2(conn, timeout)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, nil
	}

	return plugins.CreateServiceFrom(target, info, false, info.OSVersion, plugins.TCP), nil
}

func (p *SMBPlugin) Name() string {
	return SMB
}

func (p *SMBPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *SMBPlugin) Priority() int {
	return 320
}
