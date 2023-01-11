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

package telnet

import (
	"encoding/hex"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type TELNETPlugin struct{}

const TELNET = "telnet"

// https://www.rfc-editor.org/rfc/rfc854
const IAC byte = 255
const DONT byte = 254
const DO byte = 253
const WONT byte = 252
const WILL byte = 251
const SE byte = 240
const NOP byte = 241
const DM byte = 242
const BRK byte = 243
const IP byte = 244
const AO byte = 245
const AYT byte = 246
const EC byte = 247
const EL byte = 248
const GA byte = 249
const SB byte = 250

// https://users.cs.cf.ac.uk/Dave.Marshall/Internet/node141.html
const ECHO byte = 1
const SUPPRESSGOAHEAD byte = 3
const STATUS byte = 5
const TIMINGMARK byte = 6
const TERMTYPE byte = 24
const WINDOWSIZE byte = 31
const TERMSPEED byte = 32
const REMOTEFLOWCTRL byte = 33
const LINEMODE byte = 34
const ENVVAR byte = 36

// https://www.iana.org/assignments/telnet-options/telnet-options.xhtml
// Binary Transmission 	[RFC856]
// Reconnection 	[NIC 15391 of 1973]
// Approx Message Size Negotiation 	[NIC 15393 of 1973]
// Remote Controlled Trans and Echo 	[RFC726]
// Output Line Width 	[NIC 20196 of August 1978]
// Output Page Size 	[NIC 20197 of August 1978]
// Output Carriage-Return Disposition 	[RFC652]
// Output Horizontal Tab Stops 	[RFC653]
// Output Horizontal Tab Disposition 	[RFC654]
// Output Formfeed Disposition 	[RFC655]
// Output Vertical Tabstops 	[RFC656]
// Output Vertical Tab Disposition 	[RFC657]
// Output Linefeed Disposition 	[RFC658]
// Extended ASCII 	[RFC698]
// Logout 	[RFC727]
// Byte Macro 	[RFC735]
// Data Entry Terminal 	[RFC1043][RFC732]
// SUPDUP 	[RFC736][RFC734]
// SUPDUP Output 	[RFC749]
// Send Location 	[RFC779]
// End of Record 	[RFC885]
// TACACS User Identification 	[RFC927]
// Output Marking 	[RFC933]
// Terminal Location Number 	[RFC946]
// Telnet 3270 Regime 	[RFC1041]
// X.3 PAD 	[RFC1053]
// X Display Location 	[RFC1096]
// Authentication Option 	[RFC2941]
// Encryption Option 	[RFC2946]
// New Environment Option 	[RFC1572]
// TN3270E 	[RFC2355]
// XAUTH 	[Rob_Earhart]
// CHARSET 	[RFC2066]
// Telnet Remote Serial Port (RSP) 	[Robert_Barnes]
// Com Port Control Option 	[RFC2217]
// Telnet Suppress Local Echo 	[Wirt_Atmar]
// Telnet Start TLS 	[Michael_Boe]
// KERMIT 	[RFC2840]
// SEND-URL 	[David_Croft]
// FORWARD_X 	[Jeffrey_Altman]
// TELOPT PRAGMA LOGON 	[Steve_McGregory]
// TELOPT SSPI LOGON 	[Steve_McGregory]
// TELOPT PRAGMA HEARTBEAT 	[Steve_McGregory]
const BinTransmission byte = 0
const RECON byte = 2
const ApproxMsgSizeNeg byte = 4
const RemoteCtrlTE byte = 7
const OUTLINEWIDTH byte = 8
const OUTPAGESIZE byte = 9
const OUTCRD byte = 10
const OUTHTS byte = 11
const OUTHTD byte = 12
const OUTFFD byte = 13
const OUTVT byte = 14
const OUTVTD byte = 15
const OUTLD byte = 16
const EXTASCII byte = 17
const LOGOUT byte = 18
const BYTEMACRO byte = 19
const DataEntryTerm byte = 20
const SUPDUP byte = 21
const SupdupOut byte = 22
const SendLoc byte = 23
const EOR byte = 25
const TACAS byte = 26
const OM byte = 27
const TERMLOCN byte = 28
const T3270 byte = 29
const X3PAD byte = 30
const XDISP byte = 35
const AUTHOPT byte = 37
const ENCOPT byte = 38
const NEWENVOPT byte = 39
const TN327 byte = 40
const XAUTH byte = 41
const CHARSET byte = 42
const TRSP byte = 43
const COMPORT byte = 44
const TSLE byte = 45
const TSTLS byte = 46
const KERMIT byte = 47
const SENDURL byte = 48
const ForX byte = 49
const TELPL byte = 138
const TELSSPI byte = 139
const TELPRAGMA byte = 140

var TelnetCommandMap = map[byte]bool{
	IAC:  true,
	DONT: true,
	DO:   true,
	WONT: true,
	WILL: true,
	SE:   true,
	NOP:  true,
	DM:   true,
	BRK:  true,
	IP:   true,
	AO:   true,
	AYT:  true,
	EC:   true,
	EL:   true,
	GA:   true,
	SB:   true,
}

// https://users.cs.cf.ac.uk/Dave.Marshall/Internet/node141.html
// https://www.iana.org/assignments/telnet-options/telnet-options.xhtml
var TelnetOptionsMap = map[byte]bool{
	ECHO:             true,
	SUPPRESSGOAHEAD:  true,
	STATUS:           true,
	TIMINGMARK:       true,
	TERMTYPE:         true,
	WINDOWSIZE:       true,
	TERMSPEED:        true,
	REMOTEFLOWCTRL:   true,
	LINEMODE:         true,
	ENVVAR:           true,
	BinTransmission:  true,
	RECON:            true,
	ApproxMsgSizeNeg: true,
	RemoteCtrlTE:     true,
	OUTLINEWIDTH:     true,
	OUTPAGESIZE:      true,
	OUTCRD:           true,
	OUTHTS:           true,
	OUTHTD:           true,
	OUTFFD:           true,
	OUTVT:            true,
	OUTVTD:           true,
	OUTLD:            true,
	EXTASCII:         true,
	LOGOUT:           true,
	BYTEMACRO:        true,
	DataEntryTerm:    true,
	SUPDUP:           true,
	SupdupOut:        true,
	SendLoc:          true,
	EOR:              true,
	TACAS:            true,
	OM:               true,
	TERMLOCN:         true,
	T3270:            true,
	X3PAD:            true,
	XDISP:            true,
	AUTHOPT:          true,
	ENCOPT:           true,
	NEWENVOPT:        true,
	TN327:            true,
	XAUTH:            true,
	CHARSET:          true,
	TRSP:             true,
	COMPORT:          true,
	TSLE:             true,
	TSTLS:            true,
	KERMIT:           true,
	SENDURL:          true,
	ForX:             true,
	TELPL:            true,
	TELSSPI:          true,
	TELPRAGMA:        true,
}

func isTelnet(telnet []byte) error {
	msgLength := len(telnet)
	matchError := &utils.InvalidResponseError{Service: TELNET}

	if msgLength == 0 || msgLength == 1 {
		// a 0 or 1 byte response is probably not a telnet server
		// matchError.Msg = "invalid message length"
		return matchError
	}

	// the first byte must be IAC
	if telnet[0] != IAC {
		// matchError.Msg = "missing IAC first byte"
		return matchError
	}
	// if the next code isn't a valid telnet command probably not a telnet server
	if _, ok := TelnetCommandMap[telnet[1]]; !ok {
		// matchError.Msg = "invalid telnet command"
		return matchError
	}

	if msgLength == 2 {
		// the first two bytes were valid telnet speak and only two bytes were sent, good chance this is a telnet server
		return nil
	}

	// msgLength is not 0, 1, or 2 (so it's 3 or greater)
	// check if the 3rd byte is a valid telnet option, if it is this is likely a real telnet server sending:
	// IAC,<type of operation>,<option>
	// if it's not a valid option, this is probably not a telnet server
	_, ok := TelnetOptionsMap[telnet[2]]
	if ok {
		return nil
	}
	// matchError.Msg = "invalid option command"
	return matchError
}

func init() {
	plugins.RegisterPlugin(&TELNETPlugin{})
}

func (p *TELNETPlugin) PortPriority(port uint16) bool {
	return port == 23
}

func (p *TELNETPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	if err := isTelnet(response); err != nil {
		return nil, nil
	}
	payload := plugins.ServiceTelnet{
		ServerData: hex.EncodeToString(response),
	}
	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

func (p *TELNETPlugin) Name() string {
	return TELNET
}

func (p *TELNETPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *TELNETPlugin) Priority() int {
	return 4
}
