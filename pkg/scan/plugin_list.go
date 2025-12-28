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

package scan

// These import statements ensure that the init functions run in each plugin.
// When a new plugin is added, this list should be updated.

import (
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/dhcp"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/dns"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/echo"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/ftp"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/http"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/imap"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/ipmi"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/ipsec"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/jdwp"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/kafka/kafkaNew"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/kafka/kafkaOld"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/ldap"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/linuxrpc"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/modbus"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/mongodb"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/mqtt/mqtt3"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/mqtt/mqtt5"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/mssql"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/mysql"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/netbios"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/ntp"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/openvpn"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/oracledb"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/pop3"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/postgresql"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/rdp"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/redis"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/rsync"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/rtsp"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/smb"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/smtp"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/snmp"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/ssh"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/stun"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/telnet"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/vnc"
)
