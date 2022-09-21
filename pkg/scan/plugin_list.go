package scan

// These import statements ensure that the init functions run in each plugin.
// When a new plugin is added, this list should be updated.

import (
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/dhcp"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/dns"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/ftp"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/http"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/imap"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/ipsec"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/kafka/kafkaNew"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/kafka/kafkaOld"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/ldap"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/linuxrpc"
	_ "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/modbus"
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
