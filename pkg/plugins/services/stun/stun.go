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

package stun

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

const STUN = "stun"

type Plugin struct{}

var MessageHeaderLength = 20
var FingerprintAttrLength = 8
var BindingResponse = "0101"
var MagicCookie = "2112a442"
var ATTRIBUTES = map[uint32]string{
	0x0001: "MappedAddress",
	0x0006: "Username",
	0x0008: "MessageIntegrity",
	0x0009: "ErrorCode",
	0x000a: "UnknownAttributes",
	0x0014: "Realm",
	0x0015: "Nonce",
	0x0020: "XORMappedAddress",
	0x8022: "Software",
	0x8023: "AlternateServer",
	0x8028: "Fingerprint",
}
var FingerprintXor uint32 = 0x5354554e

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	/**
	 * https://datatracker.ietf.org/doc/html/rfc8489
	 *
	 * Sends binding request with FINGERPRINT attribute
	 * Checks if response contains valid message type, magic cookie, and transaction ID
	 */

	InitialConnectionPackage := []byte{
		0x00, 0x01, // Message Type (class: Request, method: Binding)
		0x00, 0x0c, // Message Length
		0x21, 0x12, 0xA4, 0x42, // Magic Cookie
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Transaction ID

		// Attribute: SOFTWARE
		0x80, 0x22, // attribute type
		0x0, 0x0, // attribute length

		// Attribute: FINGERPRINT
		0x80, 0x28, // attribute type
		0x0, 0x4, // attribute length
		0x0, 0x0, 0x0, 0x0, // CRC-32 checksum
	}
	_, err := rand.Read(InitialConnectionPackage[8:20]) // generate random transaction ID
	if err != nil {
		return nil, &utils.RandomizeError{Message: "transaction ID"}
	}
	TransactionID := hex.EncodeToString(InitialConnectionPackage[8:20])

	fingerprintValue := crc32.ChecksumIEEE(
		InitialConnectionPackage[:len(InitialConnectionPackage)-FingerprintAttrLength],
	) ^ FingerprintXor
	for i := 1; i <= 4; i++ {
		InitialConnectionPackage[len(InitialConnectionPackage)-i] = byte(fingerprintValue & 0xFF)
		fingerprintValue >>= 8
	}

	response, err := utils.SendRecv(conn, InitialConnectionPackage, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// check response
	if len(response) < MessageHeaderLength {
		return nil, nil
	}
	rmsgType, rmagicCookie, rtransID := hex.EncodeToString(response[:2]),
		hex.EncodeToString(response[4:8]),
		hex.EncodeToString(response[8:20])
	if rmsgType != BindingResponse {
		return nil, nil
	}
	if rmagicCookie != MagicCookie {
		return nil, nil
	}
	if rtransID != TransactionID {
		return nil, nil
	}

	// parse attributes (possibly optional)
	infoMap, err := parseResponse(response)
	if err != nil {
		return nil, nil
	}
	payload := plugins.ServiceStun{
		Info: fmt.Sprintf("%s", infoMap),
	}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
}

func parseResponse(response []byte) (map[string]any, error) {
	attrInfo := make(map[string]any)
	idx := MessageHeaderLength
	length := len(response)
	for idx < length {
		// parse attribute type, length
		if idx+4 > length {
			return nil, &utils.InvalidResponseErrorInfo{
				Service: "OpenVPN",
				Info:    "invalid attribute T/L header",
			}
		}
		attrType, attrLen := (int(response[idx])<<8)+int(response[idx+1]),
			(int(response[idx+2])<<8)+int(response[idx+3])
		idx += 4
		if attrLen == 0 {
			continue
		}

		// parse attribute value
		if idx+attrLen > length {
			return nil, &utils.InvalidResponseErrorInfo{
				Service: "OpenVPN",
				Info:    "invalid attribute length",
			}
		}
		attrValue := response[idx : idx+attrLen]
		idx += attrLen
		var attrValueStr string
		attrName, exists := ATTRIBUTES[uint32(attrType)]
		if exists {
			if attrName == "Software" {
				attrValueStr = string(attrValue)
			} else {
				attrValueStr = hex.EncodeToString(attrValue)
			}
		} else {
			attrName = fmt.Sprintf("%04x", attrType)
			attrValueStr = hex.EncodeToString(attrValue)
		}

		// update attribute info map
		// if attribute appeared more than once, only process first occurence
		_, exists = attrInfo[attrName]
		if !exists {
			attrInfo[attrName] = attrValueStr
		}
	}

	return attrInfo, nil
}

func (p *Plugin) PortPriority(i uint16) bool {
	return i == 3478
}

func (p *Plugin) Name() string {
	return STUN
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 2000
}
