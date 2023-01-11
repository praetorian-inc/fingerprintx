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

package dhcp

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

const DHCP = "dhcp"

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func getSignatures() map[int]string {
	signature := map[int]string{
		0:   "Pad",
		1:   "Subnet Mask",
		2:   "Time Offset",
		3:   "Router",
		4:   "Time Server",
		5:   "Name Server",
		6:   "Domain Server",
		7:   "Log Server",
		8:   "Quotes Server",
		9:   "LPR Server",
		10:  "Impress Server",
		11:  "RLP Server",
		12:  "Hostname",
		13:  "Boot File Size",
		14:  "Merit Dump File",
		15:  "Domain Name",
		16:  "Swap Server",
		17:  "Root Path",
		18:  "Extension File",
		19:  "Forward On/Off",
		20:  "SrcRte On/Off",
		21:  "Policy Filter",
		22:  "Max DG Assembly",
		23:  "Default IP TTL",
		24:  "MTU Timeout",
		25:  "MTU Plateau",
		26:  "MTU Interface",
		27:  "MTU Subnet",
		28:  "Broadcast Address",
		29:  "Mask Discovery",
		30:  "Mask Supplier",
		31:  "Router Discovery",
		32:  "Router Request",
		33:  "Static Route",
		34:  "Trailers",
		35:  "ARP Timeout",
		36:  "Ethernet",
		37:  "Default TCP TTL",
		38:  "Keepalive Time",
		39:  "Keepalive Data",
		40:  "NIS Domain",
		41:  "NIS Servers",
		42:  "NTP Servers",
		43:  "Vendor Specific",
		44:  "NETBIOS Name Srv",
		45:  "NETBIOS Dist Srv",
		46:  "NETBIOS Node Type",
		47:  "NETBIOS Scope",
		48:  "X Window Font",
		49:  "X Window Manager",
		50:  "Address Request",
		51:  "Address Time",
		52:  "Overload",
		53:  "DHCP Msg Type",
		54:  "DHCP Server Id",
		55:  "Parameter List",
		56:  "DHCP Message",
		57:  "DHCP Max Msg Size",
		58:  "Renewal Time",
		59:  "Rebinding Time",
		60:  "Class Id",
		61:  "Client Id",
		62:  "NetWare/IP Domain",
		63:  "NetWare/IP Option",
		64:  "NIS-Domain-Name",
		65:  "NIS-Server-Addr",
		66:  "Server-Name",
		67:  "Bootfile-Name",
		68:  "Home-Agent-Addrs",
		69:  "SMTP-Server",
		70:  "POP3-Server",
		71:  "NNTP-Server",
		72:  "WWW-Server",
		73:  "Finger-Server",
		74:  "IRC-Server",
		75:  "StreetTalk-Server",
		76:  "STDA-Server",
		77:  "User-Class",
		78:  "Directory Agent",
		79:  "Service Scope",
		80:  "Rapid Commit",
		81:  "Client FQDN",
		82:  "Relay Agent Information",
		83:  "iSNS",
		85:  "NDS Servers",
		86:  "NDS Tree Name",
		87:  "NDS Context",
		88:  "BCMCS Controller Domain Name list",
		89:  "BCMCS Controller IPv4 address option",
		90:  "Authentication",
		91:  "client-last-transaction-time option",
		92:  "associated-ip option",
		93:  "Client System",
		94:  "Client NDI",
		95:  "LDAP",
		97:  "UUID/GUID",
		98:  "User-Auth",
		99:  "GEOCONF_CIVIC",
		100: "PCode",
		101: "TCode",
		109: "OPTION_DHCP4O6_S46_SADDR",
		112: "Netinfo Address",
		113: "Netinfo Tag",
		114: "URL",
		116: "Auto-Config",
		117: "Name Service Search",
		118: "Subnet Selection Option",
		119: "Domain Search",
		120: "SIP Servers DHCP Option",
		121: "Classless",
		122: "CCC",
		123: "GeoConf Option",
		124: "V-I Vendor",
		125: "V-I Vendor-Specific Information",
		131: "Remote statistics server IP address",
		132: "IEEE 802.1Q VLAN ID",
		133: "IEEE 802.1D/p Layer",
		134: "Diffserv Code Point",
		135: "HTTP Proxy for phone-specific applications",
		136: "OPTION_PANA_AGENT",
		137: "OPTION_V4_LOST",
		138: "OPTION_CAPWAP_AC_V4",
		139: "OPTION-IPv4_Address-MoS",
		140: "OPTION-IPv4_FQDN-MoS",
		141: "SIP UA Configuration Service Domains",
		142: "OPTION-IPv4_Address-ANDSF",
		143: "OPTION_V4_SZTP_REDIRECT",
		144: "GeoLoc",
		145: "FORCERENEW_NONCE_CAPABLE",
		146: "RDNSS Selection",
		151: "status-code",
		152: "base-time",
		153: "start-time-of-state",
		154: "query-start-time",
		155: "query-end-time",
		156: "dhcp-state",
		157: "data-source",
		158: "OPTION_V4_PCP_SERVER",
		160: "DHCP Captive-Portal",
		161: "OPTION_MUD_URL_V4",
		175: "Etherboot",
		176: "IP Telephone",
		209: "Configuration File",
		210: "Path Prefix",
		211: "Reboot Time",
		212: "OPTION_6RD",
		213: "OPTION_V4_ACCESS_DOMAIN",
		220: "Subnet Allocation Option",
		221: "Virtual Subnet Selection",
		255: "End",
	}
	return signature
}

func hostnameParse(options []byte) []string {
	var ret string
	var retList []string
	wholePacket := options[2 : 2+int(options[1])]
	packet := wholePacket
	for len(packet) != 0 {
		length := int(packet[0])
		if len(packet) < length+1 {
			return retList
		}
		if length == 0 {
			retList = append(retList, ret)
			ret = ""
			packet = packet[1:]
		} else {
			ret += string(packet[1 : 1+length])
			packet = packet[1+length:]
			if len(packet) == 0 {
				break
			}
			if packet[0] != 0 {
				ret += "."
			}
			if packet[0] == 0xc0 && len(packet) == 2 {
				wholePacket = wholePacket[int(packet[1]) : len(wholePacket)-(4+length)]
				packet = wholePacket
			}
		}
	}
	retList = append(retList, ret)
	return retList
}

func ipParse(options []byte) []string {
	ipLen := int(options[1]) / 4
	ipList := options[2 : 2+int(options[1])]
	var ipStrList []string
	for ipLen != 0 {
		ip := fmt.Sprintf("%d.%d.%d.%d", int(ipList[0]), int(ipList[1]), int(ipList[2]), int(ipList[3]))
		ipStrList = append(ipStrList, ip)
		ipLen--
		ipList = ipList[4:]
	}
	return ipStrList
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	sliceIP := net.ParseIP("127.0.0.1")
	if sliceIP == nil {
		return nil, &utils.InvalidAddrProvided{Service: DHCP}
	}

	LocalIP := []byte{sliceIP[12], sliceIP[13], sliceIP[14], sliceIP[15]}
	InitialConnectionPackage := []byte{
		0x01, // Message type: Boot Request (1)
		0x01, // Hardware type: Ethernet (0x01)
		0x06, // Hardware address length: 6
		0x01, // Hops: 1
	}
	transactionID := make([]byte, 4)
	_, err := rand.Read(transactionID)
	if err != nil {
		return nil, &utils.RandomizeError{Message: "Transaction ID"}
	}
	InitialConnectionPackage = append(InitialConnectionPackage, transactionID...)
	SecondPartConnectionPackage := []byte{
		0x00, 0x00, // Seconds elapsed: 0
		0x00, 0x00, // Bootp flags: 0x0000 (Unicast)
	}
	InitialConnectionPackage = append(InitialConnectionPackage, SecondPartConnectionPackage...)
	IPConnectionPackage := []byte{
		0x00, 0x00, 0x00, 0x00, // Client IP address: 0.0.0.0
		0x00, 0x00, 0x00, 0x00, // Your (client) IP address: 0.0.0.0
		0x00, 0x00, 0x00, 0x00, // Next server IP address: 0.0.0.0
	}
	InitialConnectionPackage = append(InitialConnectionPackage, IPConnectionPackage...)
	InitialConnectionPackage = append(InitialConnectionPackage, LocalIP...) // Relay server IP address: LocalIP
	ClientMAC := make([]byte, 6)
	_, err = rand.Read(ClientMAC)
	if err != nil {
		return nil, &utils.RandomizeError{Message: "ClientMAC"}
	}
	InitialConnectionPackage = append(InitialConnectionPackage, ClientMAC...)
	ThirdPartConnectionPackage := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Client hardware address padding
		// Server host name
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Boot File name
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

		0x63, 0x82, 0x53, 0x63, // Magic cookie: DHCP

		0x35, 0x01, 0x01, // Option: (53) DHCP Message Type (Discover)
	}
	InitialConnectionPackage = append(InitialConnectionPackage, ThirdPartConnectionPackage...)
	InitialConnectionPackage = append(InitialConnectionPackage, 0xff) // Option: (255) End

	response, err := utils.SendRecv(conn, InitialConnectionPackage, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < 8 {
		return nil, nil
	}
	// https://ecanet.ir/dhcp-option-list/
	if bytes.Equal(transactionID, response[4:8]) {
		if len(response) <= 240 && response[len(response)-1] != 255 {
			return nil, nil
		}

		signature := getSignatures()
		options := response[240:]

		optionList := map[string]any{}
		for int(options[0]) != 255 {
			if len(options) < int(options[1])+2 {
				// packet corruption
				payload := plugins.ServiceDHCP{
					Option: fmt.Sprintf("%s", optionList),
				}
				return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
			}
			c := int(options[0])
			switch c {
			case 51, 58, 59:
				optionList[signature[c]] = big.NewInt(0).SetBytes(options[2 : 2+int(options[1])]).Uint64()
			case 119:
				outList := hostnameParse(options)
				optionList[signature[c]] = outList
			case 15:
				optionList[signature[c]] = string(options[2 : 2+int(options[1])])
			case 1:
				ipStrList := ipParse(options)
				optionList[signature[c]] = ipStrList
				if len(ipStrList) == 1 {
					optionList[signature[c]] = ipStrList[0]
				}
			case 3, 6, 28, 42, 44, 54:
				ipStrList := ipParse(options)
				optionList[signature[c]] = ipStrList
			default:
				if int(options[1]) == 1 {
					optionList[signature[c]] = int(options[2])
				} else {
					optionList[signature[c]] = options[2 : 2+int(options[1])]
				}
			}
			options = options[2+int(options[1]):]
		}
		payload := plugins.ServiceDHCP{
			Option: fmt.Sprintf("%s", optionList),
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
	}
	return nil, nil
}

func (p *Plugin) PortPriority(i uint16) bool {
	return i == 67
}

func (p *Plugin) Name() string {
	return DHCP
}

func (p *Plugin) PortReject(u uint16) bool {
	return u != 67
}

func (p *Plugin) SrcPort() uint16 {
	return 67
}

func (p *Plugin) Priority() int {
	return 100
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}
