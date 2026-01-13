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
	"strings"
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

const (
	ProtoAMQP       = "amqp"
	ProtoDNS        = "dns"
	ProtoDHCP       = "dhcp"
	ProtoDiameter   = "diameter"
	ProtoDB2        = "db2"
	ProtoCassandra  = "cassandra"
	ProtoChromaDB   = "chromadb"
	ProtoCouchDB    = "couchdb"
	ProtoEcho          = "echo"
	ProtoElasticsearch = "elasticsearch"
	ProtoFirebird      = "firebird"
	ProtoFTP           = "ftp"
	ProtoHTTP          = "http"
	ProtoHTTPS      = "https"
	ProtoHTTP2      = "http2"
	ProtoIMAP       = "imap"
	ProtoIMAPS      = "imaps"
	ProtoInfluxDB   = "influxdb"
	ProtoIPMI       = "ipmi"
	ProtoIPSEC      = "ipsec"
	ProtoJDWP       = "jdwp"
	ProtoKafka      = "kafka"
	ProtoKubernetes = "kubernetes"
	ProtoLDAP       = "ldap"
	ProtoLDAPS      = "ldaps"
	ProtoMemcached     = "memcached"
	ProtoMilvus        = "milvus"
	ProtoMilvusMetrics = "milvus-metrics"
	ProtoModbus        = "modbus"
	ProtoMongoDB    = "mongodb"
	ProtoMQTT       = "mqtt"
	ProtoMSSQL      = "mssql"
	ProtoMySQL      = "mysql"
	ProtoNeo4j      = "neo4j"
	ProtoNetbios    = "netbios"
	ProtoNTP        = "ntp"
	ProtoOracle     = "oracle"
	ProtoOpenVPN    = "openvpn"
	ProtoPinecone   = "pinecone"
	ProtoPOP3       = "pop3"
	ProtoPOP3S      = "pop3s"
	ProtoPostgreSQL = "postgresql"
	ProtoRDP        = "rdp"
	ProtoRPC        = "rpc"
	ProtoRedis      = "redis"
	ProtoRedisTLS   = "redis"
	ProtoRMI        = "java-rmi"
	ProtoRsync      = "rsync"
	ProtoRtsp       = "rtsp"
	ProtoSMB        = "smb"
	ProtoSMPP       = "smpp"
	ProtoSMTP       = "smtp"
	ProtoSMTPS      = "smtps"
	ProtoSNMP       = "snmp"
	ProtoSNPP       = "snpp"
	ProtoSSH        = "ssh"
	ProtoStun       = "stun"
	ProtoSybase     = "sybase"
	ProtoTelnet     = "telnet"
	ProtoVNC        = "vnc"
	ProtoUnknown    = "unknown"
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
	case ProtoAMQP:
		var p ServiceAMQP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoElasticsearch:
		var p ServiceElasticsearch
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoCouchDB:
		var p ServiceCouchDB
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoDiameter:
		var p ServiceDiameter
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoDB2:
		var p ServiceDB2
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoCassandra:
		var p ServiceCassandra
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoChromaDB:
		var p ServiceChromaDB
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoFirebird:
		var p ServiceFirebird
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoFTP:
		var p ServiceFTP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPostgreSQL:
		var p ServicePostgreSQL
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoVNC:
		var p ServiceVNC
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoTelnet:
		var p ServiceTelnet
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRedis:
		var p ServiceRedis
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoHTTP:
		var p ServiceHTTP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoHTTPS:
		var p ServiceHTTPS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoHTTP2:
		var p ServiceHTTP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSMB:
		var p ServiceSMB
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSMPP:
		var p ServiceSMPP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRDP:
		var p ServiceRDP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRPC:
		var p ServiceRPC
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMSSQL:
		var p ServiceMSSQL
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoNetbios:
		var p ServiceNetbios
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoKafka:
		var p ServiceKafka
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoKubernetes:
		var p ServiceKubernetes
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoOracle:
		var p ServiceOracle
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPinecone:
		var p ServicePinecone
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMySQL:
		var p ServiceMySQL
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSMTP:
		var p ServiceSMTP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSMTPS:
		var p ServiceSMTPS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoLDAP:
		var p ServiceLDAP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoModbus:
		var p ServiceModbus
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMongoDB:
		var p ServiceMongoDB
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoNeo4j:
		var p ServiceNeo4j
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoLDAPS:
		var p ServiceLDAPS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSSH:
		var p ServiceSSH
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSybase:
		var p ServiceSybase
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoIMAP:
		var p ServiceIMAP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRMI:
		var p ServiceRMI
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRsync:
		var p ServiceRsync
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRtsp:
		var p ServiceRtsp
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoIMAPS:
		var p ServiceIMAPS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoInfluxDB:
		var p ServiceInfluxDB
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMQTT:
		var p ServiceMQTT
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMemcached:
		var p ServiceMemcached
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMilvus:
		var p ServiceMilvus
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMilvusMetrics:
		var p ServiceMilvusMetrics
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPOP3:
		var p ServicePOP3
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPOP3S:
		var p ServicePOP3S
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSNPP:
		var p ServiceSNPP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	default:
		var p ServiceUnknown
		_ = json.Unmarshal(e.Raw, &p)
		return p
	}
}

type ServiceUnknown map[string]any

func (e ServiceUnknown) Type() string { return ProtoUnknown }

func (e ServiceUnknown) Map() map[string]any { return e }

func CreateServiceFrom(target Target, m Metadata, tls bool, version string, transport Protocol) *Service {
	service := Service{}
	b, _ := json.Marshal(m)

	service.Host = target.Host
	service.IP = target.Address.Addr().String()
	service.Port = int(target.Address.Port())
	service.Protocol = m.Type()
	service.Transport = strings.ToLower(transport.String())
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

type Service struct {
	Host      string          `json:"host,omitempty"`
	IP        string          `json:"ip"`
	Port      int             `json:"port"`
	Protocol  string          `json:"protocol"`
	TLS       bool            `json:"tls"`
	Transport string          `json:"transport"`
	Version   string          `json:"version,omitempty"`
	Raw       json.RawMessage `json:"metadata"`
}

type ServiceAMQP struct {
	Product  string   `json:"product,omitempty"`
	Version  string   `json:"version,omitempty"`
	Platform string   `json:"platform,omitempty"`
	CPEs     []string `json:"cpes,omitempty"`
}

func (e ServiceAMQP) Type() string { return ProtoAMQP }

type ServiceHTTP struct {
	Status          string      `json:"status"`     // e.g. "200 OK"
	StatusCode      int         `json:"statusCode"` // e.g. 200
	ResponseHeaders http.Header `json:"responseHeaders"`
	Technologies    []string    `json:"technologies,omitempty"`
	CPEs            []string    `json:"cpes,omitempty"`
}

func (e ServiceHTTP) Type() string { return ProtoHTTP }

type ServiceHTTPS struct {
	Status          string      `json:"status"`     // e.g. "200 OK"
	StatusCode      int         `json:"statusCode"` // e.g. 200
	ResponseHeaders http.Header `json:"responseHeaders"`
	Technologies    []string    `json:"technologies,omitempty"`
	CPEs            []string    `json:"cpes,omitempty"`
}

func (e ServiceHTTPS) Type() string { return ProtoHTTPS }

type ServiceRDP struct {
	OSFingerprint       string `json:"fingerprint,omitempty"` // e.g. Windows Server 2016 or 2019
	OSVersion           string `json:"osVersion,omitempty"`
	TargetName          string `json:"targetName,omitempty"`
	NetBIOSComputerName string `json:"netBIOSComputerName,omitempty"`
	NetBIOSDomainName   string `json:"netBIOSDomainName,omitempty"`
	DNSComputerName     string `json:"dnsComputerName,omitempty"`
	DNSDomainName       string `json:"dnsDomainName,omitempty"`
	ForestName          string `json:"forestName,omitempty"`
}

func (e ServiceRDP) Type() string { return ProtoRDP }

type ServiceRPC struct {
	Entries []RPCB `json:"entries"`
}

type RPCB struct {
	Program  int    `json:"program"`
	Version  int    `json:"version"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Owner    string `json:"owner"`
}

func (e ServiceRPC) Type() string { return ProtoRPC }

type ServiceSMB struct {
	SigningEnabled      bool   `json:"signingEnabled"`  // e.g. Is SMB Signing Enabled?
	SigningRequired     bool   `json:"signingRequired"` // e.g. Is SMB Signing Required?
	OSVersion           string `json:"osVersion"`
	NetBIOSComputerName string `json:"netBIOSComputerName,omitempty"`
	NetBIOSDomainName   string `json:"netBIOSDomainName,omitempty"`
	DNSComputerName     string `json:"dnsComputerName,omitempty"`
	DNSDomainName       string `json:"dnsDomainName,omitempty"`
	ForestName          string `json:"forestName,omitempty"`
}

func (e ServiceSMB) Type() string { return ProtoSMB }

type ServiceMySQL struct {
	PacketType   string   `json:"packetType"`       // the type of packet returned by the server (i.e. handshake or error)
	ErrorMessage string   `json:"errorMsg"`         // error message if the server returns an error packet
	ErrorCode    int      `json:"errorCode"`        // error code returned if the server returns an error packet
	CPEs         []string `json:"cpes,omitempty"`   // Common Platform Enumeration identifiers for vulnerability tracking
}

func (e ServiceMySQL) Type() string { return ProtoMySQL }

func (e ServicePostgreSQL) Type() string { return ProtoPostgreSQL }

type ServicePostgreSQL struct {
	AuthRequired bool     `json:"authRequired"`
	CPEs         []string `json:"cpes,omitempty"`
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

type ServiceSNPP struct {
	Banner string `json:"banner"`
}

func (e ServiceSNPP) Type() string { return ProtoSNPP }

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

type ServiceInfluxDB struct {
	CPEs []string `json:"cpes,omitempty"` // Common Platform Enumeration identifiers for vulnerability tracking
}

func (e ServiceInfluxDB) Type() string { return ProtoInfluxDB }

type ServiceIPSEC struct {
	ResponderISP string `json:"responderISP"`
	MessageID    string `json:"messageID"`
}

func (e ServiceIPSEC) Type() string { return ProtoIPSEC }

type ServiceMSSQL struct {
	CPEs []string `json:"cpes,omitempty"` // Common Platform Enumeration identifiers for vulnerability tracking
}

func (e ServiceMSSQL) Type() string { return ProtoMSSQL }

type ServiceVNC struct{}

func (e ServiceVNC) Type() string { return ProtoVNC }

type ServiceTelnet struct {
	ServerData string `json:"serverData"`
}

func (e ServiceTelnet) Type() string { return ProtoTelnet }

type ServiceRedis struct {
	AuthRequired bool     `json:"authRequired:"`
	CPEs         []string `json:"cpes,omitempty"`
}

func (e ServiceRedis) Type() string { return ProtoRedis }

type ServiceElasticsearch struct {
	CPEs []string `json:"cpes,omitempty"` // Common Platform Enumeration identifiers for vulnerability tracking
}

func (e ServiceElasticsearch) Type() string { return ProtoElasticsearch }

type ServiceFTP struct {
	Banner     string   `json:"banner"`
	Confidence string   `json:"confidence,omitempty"` // Detection confidence: "high", "medium", or "low"
	CPEs       []string `json:"cpes,omitempty"`
}

func (e ServiceFTP) Type() string { return ProtoFTP }

type ServiceSMPP struct {
	CPEs            []string `json:"cpes,omitempty"`            // Common Platform Enumeration identifiers for vulnerability tracking
	ProtocolVersion string   `json:"protocolVersion,omitempty"` // SMPP protocol version (e.g., "3.4", "5.0")
	SystemID        string   `json:"systemID,omitempty"`        // System ID from bind_transceiver_resp
	Vendor          string   `json:"vendor,omitempty"`          // Vendor identified from system_id
	Product         string   `json:"product,omitempty"`         // Product identified from system_id
}

func (e ServiceSMPP) Type() string { return ProtoSMPP }

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

type ServiceStun struct {
	Info string `json:"info"`
}

func (e ServiceStun) Type() string { return ProtoStun }

type ServiceSSH struct {
	Banner              string `json:"banner"`
	PasswordAuthEnabled bool   `json:"passwordAuthEnabled"`
	Algo                string `json:"algo"`
	HostKey             string `json:"hostKey,omitempty"`
	HostKeyType         string `json:"hostKeyType,omitempty"`
	HostKeyFingerprint  string `json:"hostKeyFingerprint,omitempty"`
}

func (e ServiceSSH) Type() string { return ProtoSSH }

type ServiceSybase struct {
	CPEs    []string `json:"cpes,omitempty"`
	Version string   `json:"version,omitempty"`
}

func (e ServiceSybase) Type() string { return ProtoSybase }

type ServiceLDAP struct{}

func (e ServiceLDAP) Type() string { return ProtoLDAP }

type ServiceLDAPS struct{}

func (e ServiceLDAPS) Type() string { return ProtoLDAPS }

type ServiceKafka struct{}

func (e ServiceKafka) Type() string { return ProtoKafka }

type ServiceKubernetes struct {
	CPEs         []string `json:"cpes,omitempty"`
	GitVersion   string   `json:"gitVersion,omitempty"`
	GitCommit    string   `json:"gitCommit,omitempty"`
	BuildDate    string   `json:"buildDate,omitempty"`
	GoVersion    string   `json:"goVersion,omitempty"`
	Platform     string   `json:"platform,omitempty"`
	Distribution string   `json:"distribution,omitempty"` // k3s, gke, eks, aks, openshift, minikube, vanilla
	Vendor       string   `json:"vendor,omitempty"`       // kubernetes, rancher, google, aws, azure, redhat
}

func (e ServiceKubernetes) Type() string { return ProtoKubernetes }

type ServiceOracle struct {
	Info string `json:"info"`
}

func (e ServiceOracle) Type() string { return ProtoOracle }

type ServicePinecone struct {
	CPEs       []string `json:"cpes,omitempty"`  // Common Platform Enumeration with wildcard version
	APIVersion string   `json:"apiVersion,omitempty"` // Pinecone API version from x-pinecone-api-version header
}

func (e ServicePinecone) Type() string { return ProtoPinecone }

type ServiceOpenVPN struct{}

func (e ServiceOpenVPN) Type() string { return ProtoOpenVPN }

type ServiceMQTT struct{}

func (e ServiceMQTT) Type() string { return ProtoMQTT }

type ServiceMemcached struct {
	Version string   `json:"version,omitempty"`
	CPEs    []string `json:"cpes,omitempty"`
}

func (e ServiceMemcached) Type() string { return ProtoMemcached }

type ServiceMilvus struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceMilvus) Type() string { return ProtoMilvus }

type ServiceMilvusMetrics struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceMilvusMetrics) Type() string { return ProtoMilvusMetrics }

type ServiceModbus struct{}

func (e ServiceModbus) Type() string { return ProtoModbus }

type ServiceMongoDB struct {
	MaxWireVersion int      `json:"maxWireVersion,omitempty"` // Wire protocol version (indicates capabilities, NOT precise version; e.g., wire 21 = MongoDB 7.0.x)
	MinWireVersion int      `json:"minWireVersion,omitempty"` // Minimum wire protocol version supported
	ServerType     string   `json:"serverType,omitempty"`     // "mongod" or "mongos"
	CPEs           []string `json:"cpes,omitempty"`
}

func (e ServiceMongoDB) Type() string { return ProtoMongoDB }

type ServiceNeo4j struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceNeo4j) Type() string { return ProtoNeo4j }

type ServiceRtsp struct {
	ServerInfo string `json:"serverInfo"`
}

func (e ServiceRtsp) Type() string { return ProtoRtsp }

type ServiceDNS struct{}

func (e ServiceDNS) Type() string { return ProtoDNS }

type ServiceDHCP struct {
	Option string `json:"option"`
}

func (e ServiceDHCP) Type() string { return ProtoDHCP }

type ServiceCouchDB struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceCouchDB) Type() string { return ProtoCouchDB }

type ServiceDiameter struct {
	CPEs    []string `json:"cpes,omitempty"`
	Version string   `json:"version,omitempty"`
	Vendor  string   `json:"vendor,omitempty"`
	Product string   `json:"product,omitempty"`
}

func (e ServiceDiameter) Type() string { return ProtoDiameter }

type ServiceDB2 struct {
	ServerName string   `json:"serverName,omitempty"` // DB2 instance name
	CPEs       []string `json:"cpes,omitempty"`
}

func (e ServiceDB2) Type() string { return ProtoDB2 }

type ServiceCassandra struct {
	Product          string   `json:"product,omitempty"`          // "Apache Cassandra", "ScyllaDB", "DataStax Enterprise"
	CQLVersion       string   `json:"cqlVersion,omitempty"`       // CQL version from SUPPORTED response (e.g., "3.4.5")
	ProtocolVersions []string `json:"protocolVersions,omitempty"` // Native protocol versions (e.g., ["3/v3", "4/v4", "5/v5"])
	Compression      []string `json:"compression,omitempty"`      // Compression algorithms (e.g., ["lz4", "snappy", "zstd"])
	Confidence       string   `json:"confidence,omitempty"`       // Version detection confidence ("high", "medium", "low")
	CPEs             []string `json:"cpes,omitempty"`
}

func (e ServiceCassandra) Type() string { return ProtoCassandra }

type ServiceChromaDB struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceChromaDB) Type() string { return ProtoChromaDB }

type ServiceEcho struct{}

func (e ServiceEcho) Type() string { return ProtoEcho }

type ServiceFirebird struct {
	ProtocolVersion int32    `json:"protocol_version,omitempty"`
	CPEs            []string `json:"cpes,omitempty"`
}

func (e ServiceFirebird) Type() string { return ProtoFirebird }

type ServiceIPMI struct{}

func (e ServiceIPMI) Type() string { return ProtoIPMI }

type ServiceRsync struct{}

func (e ServiceRsync) Type() string { return ProtoRsync }

type ServiceJDWP struct {
	Description string `json:"description"`
	JdwpMajor   int32  `json:"jdwpMajor"`
	JdwpMinor   int32  `json:"jdwpMinor"`
	VMVersion   string `json:"VMVersion"`
	VMName      string `json:"VMName"`
}

func (e ServiceJDWP) Type() string { return ProtoJDWP }

type ServiceRMI struct {
	Endpoint string   `json:"endpoint,omitempty"`
	CPEs     []string `json:"cpes,omitempty"`
}

func (e ServiceRMI) Type() string { return ProtoRMI }
