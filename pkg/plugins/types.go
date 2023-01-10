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

package plugins

import (
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// type SupportedIPVersion uint64
type Protocol uint64

const (
	IP Protocol = iota + 1
	UDP
	TCP
	TCPTLS
)

const TypeService string = "service"

// const (
// 	IPv4 SupportedIPVersion = 1 << iota
// 	IPv6
// )

const (
	ProtoAMQP       = "amqp"
	ProtoDNS        = "dns"
	ProtoDHCP       = "dhcp"
	ProtoFTP        = "ftp"
	ProtoHTTP       = "http"
	ProtoHTTPS      = "https"
	ProtoHTTP2      = "http2"
	ProtoIMAP       = "imap"
	ProtoIMAPS      = "imaps"
	ProtoIPSEC      = "ipsec"
	ProtoKafka      = "kafka"
	ProtoKerberos   = "kerberos"
	ProtoLDAP       = "ldap"
	ProtoLDAPS      = "ldaps"
	ProtoModbus     = "modbus"
	ProtoMongoDB    = "mongodb"
	ProtoMQTT       = "mqtt"
	ProtoMSSQL      = "mssql"
	ProtoMySQL      = "mysql"
	ProtoNetbios    = "netbios"
	ProtoNTP        = "ntp"
	ProtoOracle     = "oracle"
	ProtoOpenVPN    = "openvpn"
	ProtoPOP3       = "pop3"
	ProtoPOP3S      = "pop3s"
	ProtoPostgreSQL = "postgresql"
	ProtoRDP        = "rdp"
	ProtoRPC        = "rpc"
	ProtoRedis      = "redis"
	ProtoRsync      = "rsync"
	ProtoRtsp       = "rtsp"
	ProtoSMB        = "smb"
	ProtoSMTP       = "smtp"
	ProtoSMTPS      = "smtps"
	ProtoSNMP       = "snmp"
	ProtoSSH        = "ssh"
	ProtoTelnet     = "telnet"
	ProtoVNC        = "vnc"
	ProtoZMTP       = "zmtp"
	ProtoUnknown    = "unknown"
	ProtoNmap       = "nmap"
)

// Used as a key for maps to plugins.
// i.e.: map[Service] Plugin
type PluginID struct {
	name     string
	protocol Protocol
}

type Metadata interface {
	Type() string
}

func (e Service) Type() string { return TypeService }

func (e Service) Metadata() Metadata {
	switch e.Protocol {
	case ProtoFTP:
		var p ServiceFTP
		json.Unmarshal(e.Raw, &p)
		return p
	default:
		var p ServiceUnknown
		json.Unmarshal(e.Raw, &p)
		return p
	}
}

type ServiceUnknown map[string]any

func (e ServiceUnknown) Type() string { return ProtoUnknown }

func (e ServiceUnknown) Map() map[string]any { return e }

// type PluginConfig struct {
// 	Timeout time.Duration
// }

// type PluginResults struct {
// 	Info map[string]any
// }

func CreateServiceFrom(target Target, m Metadata, tls bool, version string) *Service {
	service := Service{}
	b, _ := json.Marshal(m)

	service.Host = target.Host
	service.Port = int(target.Address.Port())
	service.Protocol = m.Type()
	service.Raw = json.RawMessage(b)
	if version != "" {
		service.Version = version
	}
	service.TLS = tls

	return &service
}

type Target struct {
	Address netip.AddrPort
	Host    string
}

type Plugin interface {
	Run(net.Conn, time.Duration, Target) (*Service, error)
	PortPriority(uint16) bool
	Name() string
	Type() Protocol
	Priority() int
}

// type PluginExtended interface {
// 	Plugin
//
// 	// Return true if the dst port must be skipped
// 	PortReject(uint16) bool
//
// 	// Return 0 if any src port is allowed
// 	SrcPort() uint16
//
// 	SupportedIPVersion() SupportedIPVersion
// }

type Service struct {
	Host     string          `json:"host"`
	IP       string          `json:"ip"`
	Port     int             `json:"port"`
	Protocol string          `json:"protocol"`
	TLS      bool            `json:"tls"`
	Version  string          `json:"version"`
	Raw      json.RawMessage `json:"metadata"`
}

type ServiceHTTP struct {
	Status          string      `json:"status"`     // e.g. "200 OK"
	StatusCode      int         `json:"statusCode"` // e.g. 200
	ResponseHeaders http.Header `json:"responseHeaders"`
	Technologies    []string    `json:"technologies"`
}

func (e ServiceHTTP) Type() string { return ProtoHTTP }

type ServiceHTTPS struct {
	Status          string      `json:"status"`     // e.g. "200 OK"
	StatusCode      int         `json:"statusCode"` // e.g. 200
	ResponseHeaders http.Header `json:"responseHeaders"`
	Technologies    []string    `json:"technologies"`
}

func (e ServiceHTTPS) Type() string { return ProtoHTTPS }

type ServiceRDP struct {
	OSFingerprint string `json:"fingerprint"` // e.g. Windows Server 2016 or 2019
	Info          string `json:"info"`        // map[string]any
}

func (e ServiceRDP) Type() string { return ProtoRDP }

type ServiceSMB struct {
	SigningEnabled      bool   `json:"signingEnabled"`  // e.g. Is SMB Signing Enabled?
	SigningRequired     bool   `json:"signingRequired"` // e.g. Is SMB Signing Required?
	OSVersion           string `json:"osVersion"`
	NetBIOSComputerName string `json:"netBIOSComputerName"`
	NetBIOSDomainName   string `json:"netBIOSDomainName"`
	DNSComputerName     string `json:"dnsComputerName"`
	DNSDomainName       string `json:"dnsDomainName"`
	ForestName          string `json:"forestName"`
}

func (e ServiceSMB) Type() string { return ProtoSMB }

type ServiceMySQL struct {
	PacketType   string `json:"packetType"` // the type of packet returned by the server (i.e. handshake or error)
	ErrorMessage string `json:"errorMsg"`   // error message if the server returns an error packet
	ErrorCode    int    `json:"errorCode"`  // error code returned if the server returns an error packet
}

func (e ServiceMySQL) Type() string { return ProtoMySQL }

func (e ServicePostgreSQL) Type() string { return ProtoPostgreSQL }

type ServicePostgreSQL struct {
	AuthRequired bool `json:"authRequired"`
}

type ServicePOP3 struct {
	Banner string `json:"banner"`
}

func (e ServicePOP3) Type() string { return ProtoPOP3 }

type ServicePOP3S struct {
	Banner string `json:"banner"`
}

func (e ServicePOP3S) Type() string { return ProtoPOP3S }

type ServiceSNMP struct{}

func (e ServiceSNMP) Type() string { return ProtoSNMP }

type ServiceNTP struct{}

func (e ServiceNTP) Type() string { return ProtoNTP }

type ServiceNetbios struct {
	NetBIOSName string `json:"netBIOSName"`
}

func (e ServiceNetbios) Type() string { return ProtoNetbios }

type ServiceIMAP struct {
	Banner string `json:"banner"`
}

func (e ServiceIMAP) Type() string { return ProtoIMAP }

type ServiceIMAPS struct {
	Banner string `json:"banner"`
}

func (e ServiceIMAPS) Type() string { return ProtoIMAPS }

type ServiceIPSEC struct {
	ResponderISP string `json:"responderISP"`
	MessageID    string `json:"messageID"`
}

func (e ServiceIPSEC) Type() string { return ProtoIPSEC }

type ServiceRPC struct {
	Info string `json:"info"`
}

func (e ServiceRPC) Type() string { return ProtoRPC }

type ServiceMSSQL struct {
}

func (e ServiceMSSQL) Type() string { return ProtoMSSQL }

type ServiceVNC struct{}

func (e ServiceVNC) Type() string { return ProtoVNC }

type ServiceTelnet struct {
	ServerData string `json:"serverData"`
}

func (e ServiceTelnet) Type() string { return ProtoTelnet }

type ServiceRedis struct {
	AuthRequired bool `json:"authRequired:"`
}

func (e ServiceRedis) Type() string { return ProtoRedis }

type ServiceFTP struct {
	Banner         string `json:"banner"`
	AnonymousLogin bool   `json:"anonymousLogin"`
}

func (e ServiceFTP) Type() string { return ProtoFTP }

type ServiceSMTP struct {
	Banner      string   `json:"banner"`
	AuthMethods []string `json:"auth_methods"`
}

func (e ServiceSMTP) Type() string { return ProtoSMTP }

type ServiceSMTPS struct {
	Banner      string   `json:"banner"`
	AuthMethods []string `json:"auth_methods"`
}

func (e ServiceSMTPS) Type() string { return ProtoSMTPS }

type ServiceSSH struct {
	Banner string `json:"banner"`
}

func (e ServiceSSH) Type() string { return ProtoSSH }

type ServiceNmap struct {
	NmapOutput string `json:"nmapOutput"`
	Service    string `json:"service"`
	Version    string `json:"version"`
}

func (e ServiceNmap) Type() string { return ProtoNmap }

type ServiceLDAP struct{}

func (e ServiceLDAP) Type() string { return ProtoLDAP }

type ServiceLDAPS struct{}

func (e ServiceLDAPS) Type() string { return ProtoLDAPS }

type ServiceKafka struct{}

func (e ServiceKafka) Type() string { return ProtoKafka }

type ServiceKerberos struct{}

func (e ServiceKerberos) Type() string { return ProtoKerberos }

type ServiceOracle struct {
	Info string `json:"info"`
}

func (e ServiceOracle) Type() string { return ProtoOracle }

type ServiceOpenVPN struct{}

func (e ServiceOpenVPN) Type() string { return ProtoOpenVPN }

type ServiceMQTT struct{}

func (e ServiceMQTT) Type() string { return ProtoMQTT }

type ServiceModbus struct{}

func (e ServiceModbus) Type() string { return ProtoModbus }

type ServiceRtsp struct {
	ServerInfo string `json:"serverInfo"`
}

func (e ServiceRtsp) Type() string { return ProtoRtsp }

type ServiceDNS struct {
	ResponseTXT string `json:"responseTXT"`
}

func (e ServiceDNS) Type() string { return ProtoDNS }

type ServiceDHCP struct {
	Option string `json:"option"`
}

func (e ServiceDHCP) Type() string { return ProtoDHCP }

type ServiceRsync struct{}

func (e ServiceRsync) Type() string { return ProtoRsync }
