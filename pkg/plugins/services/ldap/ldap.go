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

package ldap

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type LDAPPlugin struct{}
type TLSPlugin struct{}

const LDAP = "ldap"
const LDAPS = "ldaps"

func init() {
	plugins.RegisterPlugin(&LDAPPlugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

/*

Data is BER encoded (Basic Encoding Rules) - Format: Type-Length-Value

Type:
	Format of Types: Bits 	 8-7	6					5-1
					 Purpose Class Prim/Constructed		Tag Number

	For example 00 11 00 00 represents the Class (Universal) Constructed Sequence (Sequence is tag number 1 00 00)
	Ie: The sequence tag
Length:
	Single Byte - Length is a single byte containing the number of bytes in the message up to 127
	Multi Bsyte - The most significant bit is set to 1. The remaining 7 bytes are used to indicate how
	many bytes are needed to represent the length, followed by that many bytes



Example Bind Request
0000   30 2b 02 01 01 60 26 02 01 03 04 1a 63 6e 3d 61
0010   64 6d 69 6e 2c 64 63 3d 65 78 61 6d 70 6c 65 2c
0020   64 63 3d 6f 72 67 80 05 61 64 6d 69 6e

Notes:

The messageId MUST be non-zero and different from any other request in the session

30 2b ... Represents a universal sequence containing 43 bytes

02 01 01 Represents an Integer (02) type, length 1 byte, and value of 1
    (denoting a message Id of 1) - this number is reflected back in responses

60 26 denotes a bind request of 38 bytes

02 01 03 represents an integer of 1 byte with a value of 3 (the protocol version)

04 1a 63 6e 3d 61 64 6d 69 6e 2c 64 63 3d 65 78 61 6d 70 6c 65 2c 64 63 3d 6f 72 67
Represents a universal string (04) of length 26 bytes containing the value 'cn=admin,dc=example,dc=org'

80 05 61 64 6d 69 6e Represents a context specific 5 length string holding the simple auth password of 'admin'

*/

func generateRandomString(length int) []byte {
	charset := "abcdefghijklmnopqrstuvwxyz"
	result := make([]byte, length)

	for i := range result {
		result[i] = charset[rand.Intn(len(charset))] //nolint:gosec
	}
	return result
}

func generateBindRequestAndID() [2][]byte {
	rand.Seed(time.Now().UnixNano())
	sequenceBERHeader := [2]byte{0x30, 0x3a}
	messageID := uint32(rand.Int31()) //nolint:gosec
	messageIDBytes := [4]byte{}
	binary.BigEndian.PutUint32(messageIDBytes[:], messageID)
	messageIDBERHeader := [2]byte{0x02, 0x04}
	finalMessageIDBER := make([]byte, 6)
	copy(finalMessageIDBER[:2], messageIDBERHeader[:])
	copy(finalMessageIDBER[2:], messageIDBytes[:])
	bindRequestHeader := [2]byte{0x60, 0x32}
	versionBER := [3]byte{0x02, 0x01, 0x03}
	stringBERHeader := [2]byte{0x04, 0x17}
	stringContextBERHeader := [2]byte{0x80, 0x14}
	// We attempt to auth with a random distinguished name and password (generated below)
	randomAlphaString := generateRandomString(20)
	dePrefix := []byte("cn=")
	distinguishedName := append(dePrefix, randomAlphaString...) //nolint:gocritic
	passwordBER := randomAlphaString
	combine := [][]byte{
		sequenceBERHeader[:],
		finalMessageIDBER,
		bindRequestHeader[:],
		versionBER[:],
		stringBERHeader[:],
		distinguishedName,
		stringContextBERHeader[:],
		passwordBER,
	}
	fullBindRequest := make([]byte, 60)
	index := 0
	for _, s := range combine {
		index += copy(fullBindRequest[index:], s)
	}

	return [2][]byte{fullBindRequest, finalMessageIDBER}
}

func DetectLDAP(conn net.Conn, timeout time.Duration) (bool, error) {
	requestAndID := generateBindRequestAndID()

	response, err := utils.SendRecv(conn, requestAndID[0], timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return false, nil
	}

	expectedSequenceByte := byte(0x30)
	expectedMessageLengthByte := byte(len(response) - 2)
	// The LDAP header should have the right message ID bytes, the right sequence byte (the first byte),
	// and the right length byte
	expectedLDAPHeader := append(
		[]byte{expectedSequenceByte, expectedMessageLengthByte},
		requestAndID[1]...)

	// We might be able to try to look at the specific response message in responseBuff to try to fingerprint the specific
	// vendor, but didn't attempt to do that in this current version (might be more time than value added currently)

	// In other versions, bytes at response[1:5] may differ so we remove these bytes and
	// perform the expected header check against this 'otherVersionResponse' as well
	if len(response) < 7 {
		return false, nil
	}
	otherVersionResponse := append([]byte{response[0]}, response[5]+4)
	otherVersionResponse = append(otherVersionResponse, response[6:]...)

	if bytes.HasPrefix(response, expectedLDAPHeader) || bytes.HasPrefix(otherVersionResponse, expectedLDAPHeader) {
		return true, nil
	}
	return false, nil
}

func (p *LDAPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	isLDAP, err := DetectLDAP(conn, timeout)
	if err != nil {
		return nil, err
	}

	if isLDAP {
		return plugins.CreateServiceFrom(target, plugins.ServiceLDAP{}, false, "", plugins.TCP), nil
	}
	return nil, nil
}

func (p *LDAPPlugin) PortPriority(i uint16) bool {
	return i == 389
}

func (p *LDAPPlugin) Name() string {
	return LDAP
}

func (p *LDAPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	isLDAPS, err := DetectLDAP(conn, timeout)
	if err != nil {
		return nil, err
	}

	if isLDAPS {
		return plugins.CreateServiceFrom(target, plugins.ServiceLDAPS{}, true, "", plugins.TCP), nil
	}
	return nil, nil
}

func (p *TLSPlugin) PortPriority(i uint16) bool {
	return i == 636
}

func (p *LDAPPlugin) Priority() int {
	return 175
}

func (p *TLSPlugin) Priority() int {
	return 175
}

func (p *TLSPlugin) Name() string {
	return LDAPS
}

func (p *TLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}
