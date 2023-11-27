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

package linuxrpc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

/*
The RPC service takes two main operations we care about: call and dump.

Call verify that the service is running and will return the version of rpc running
Dump dumps a list of all registered rpc endpoints in a list, with each entry having the following structure:

RPCB
Program: Portmap (100000)
Version: 4
Network Id: tcp6
	length: 4
	contents: tcp6
Universal Address: ::.0.111
	length: 8
	contents: ::.0.111
Owner of this Service: superuser
	length: 9
	contents: superuser
	fill bytes: opaque data
Value follows: Yes

Bytes are padded to 4 bytes
*/

type RPCPlugin struct{}

const RPC = "RPC"

func init() {
	plugins.RegisterPlugin(&RPCPlugin{})
}

func (p *RPCPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	rpcService := plugins.ServiceRPC{}

	check, err := DetectRPCInfoService(conn, &rpcService, timeout)
	if check && err != nil {
		return nil, nil
	}
	if err == nil {
		return plugins.CreateServiceFrom(target, rpcService, false, "", plugins.TCP), nil
	}
	return nil, err
}

func DetectRPCInfoService(conn net.Conn, lookupResponse *plugins.ServiceRPC, timeout time.Duration) (bool, error) {
	callPacket := []byte{
		0x80, 0x00, 0x00, 0x28, 0x72, 0xfe, 0x1d, 0x13,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x01, 0x86, 0xa0, 0x00, 0x01, 0x97, 0x7c,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	callResponseSignature := []byte{
		0x72, 0xfe, 0x1d, 0x13, 0x00, 0x00, 0x00, 0x01,
	}

	dumpPacket := []byte{
		0x80, 0x00, 0x00, 0x28, 0x3d, 0xd3, 0x77, 0x29,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x01, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	response, err := utils.SendRecv(conn, callPacket, timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return true, &utils.ServerNotEnable{}
	}

	if !bytes.Contains(response, callResponseSignature) {
		return true, &utils.InvalidResponseError{Service: RPC}
	}

	response, err = utils.SendRecv(conn, dumpPacket, timeout)
	if err != nil {
		return false, err
	}
	if len(response) == 0 {
		return true, &utils.ServerNotEnable{}
	}

	return true, parseRPCInfo(response, lookupResponse)
}

func parseRPCInfo(response []byte, lookupResponse *plugins.ServiceRPC) error {
	if len(response) < 0x20 {
		return fmt.Errorf("invalid rpc length")
	}
	response = response[0x20:]
	valueFollows := 1

	for valueFollows == 1 {
		tmp := plugins.RPCB{}
		if len(response) < 0x20 {
			return nil
		}

		tmp.Program = int(binary.BigEndian.Uint32(response[0:4]))
		response = response[4:]
		tmp.Version = int(binary.BigEndian.Uint32(response[0:4]))
		response = response[4:]
		networkIDLen := int(binary.BigEndian.Uint32(response[0:4]))
		for networkIDLen%4 != 0 {
			networkIDLen++
		}
		response = response[4:]
		tmp.Protocol = string(response[0:networkIDLen])
		response = response[networkIDLen:]
		addressLen := int(binary.BigEndian.Uint32(response[0:4]))
		for addressLen%4 != 0 {
			addressLen++
		}
		response = response[4:]
		tmp.Address = string(response[0:addressLen])
		response = response[addressLen:]
		ownerLen := int(binary.BigEndian.Uint32(response[0:4]))
		for ownerLen%4 != 0 {
			ownerLen++
		}
		response = response[4:]
		tmp.Owner = string(response[0:ownerLen])
		response = response[ownerLen:]

		valueFollows = int(binary.BigEndian.Uint32(response[0:4]))
		response = response[4:]

		lookupResponse.Entries = append(lookupResponse.Entries, tmp)
	}

	return nil
}

func (p *RPCPlugin) PortPriority(i uint16) bool {
	return i == 111
}

func (p *RPCPlugin) Name() string {
	return RPC
}

func (p *RPCPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *RPCPlugin) Priority() int {
	return 300
}
