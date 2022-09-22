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

package pluginutils

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

func Send(conn net.Conn, data []byte, timeout time.Duration) error {
	err := conn.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		return &WriteTimeoutError{WrappedError: err}
	}
	length, err := conn.Write(data)
	if err != nil {
		return &WriteError{WrappedError: err}
	}
	if length < len(data) {
		return &WriteError{
			WrappedError: fmt.Errorf(
				"Failed to write all bytes (%d bytes written, %d bytes expected)",
				length,
				len(data),
			),
		}
	}
	return nil
}

func Recv(conn net.Conn, timeout time.Duration) ([]byte, error) {
	response := make([]byte, 4096)
	err := conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return []byte{}, &ReadTimeoutError{WrappedError: err}
	}
	length, err := conn.Read(response)
	if err != nil {
		var netErr net.Error
		if (errors.As(err, &netErr) && netErr.Timeout()) ||
			errors.Is(err, syscall.ECONNREFUSED) { // timeout error or connection refused
			return []byte{}, nil
		}
		return response[:length], &ReadError{
			Info:         hex.EncodeToString(response[:length]),
			WrappedError: err,
		}
	}
	return response[:length], nil
}

func SendRecv(conn net.Conn, data []byte, timeout time.Duration) ([]byte, error) {
	err := Send(conn, data, timeout)
	if err != nil {
		return []byte{}, err
	}
	return Recv(conn, timeout)
}
