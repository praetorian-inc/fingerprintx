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

import "fmt"

type RandomizeError struct {
	Message string
}

type InvalidResponseError struct {
	Service string
}

type InvalidResponseErrorInfo struct {
	Service string
	Info    string
}

type WriteTimeoutError struct {
	WrappedError error
}

type ReadTimeoutError struct {
	WrappedError error
}

type WriteError struct {
	WrappedError error
}

type ReadError struct {
	Info         string
	WrappedError error
}

type CreateDialError struct {
	Message string
}

type CloseDialError struct {
}

type RequestError struct {
	Message string
}

type ServerNotEnable struct {
}

type InvalidAddrProvided struct {
	Service string
}

func (e *RandomizeError) Error() string {
	return fmt.Sprintf("failed to generate random bytes [%s]", e.Message)
}

func (e *InvalidResponseError) Error() string {
	return fmt.Sprintf("invalid %s response", e.Service)
}

func (e *InvalidResponseErrorInfo) Error() string {
	return fmt.Sprintf("invalid %s response, %s", e.Service, e.Info)
}

func (e *WriteTimeoutError) Error() string {
	errString := "failed to set timeout value for write"
	if e.WrappedError != nil {
		errString = fmt.Sprintf("%s (Error: %s)", errString, e.WrappedError.Error())
	}
	return errString
}

func (e *WriteTimeoutError) Unwrap() error {
	return e.WrappedError
}

func (e *ReadTimeoutError) Error() string {
	errString := "failed to set timeout value for read"
	if e.WrappedError != nil {
		errString = fmt.Sprintf("%s (Error: %s)", errString, e.WrappedError.Error())
	}
	return errString
}

func (e *ReadTimeoutError) Unwrap() error {
	return e.WrappedError
}

func (e *WriteError) Error() string {
	errString := "failed to send out packet"
	if e.WrappedError != nil {
		errString = fmt.Sprintf("%s (Error: %s)", errString, e.WrappedError.Error())
	}
	return errString
}

func (e *WriteError) Unwrap() error {
	return e.WrappedError
}

func (e *ReadError) Error() string {
	errString := "failed to receive packet"
	if len(e.Info) > 0 {
		errString = fmt.Sprintf("%s (Info: %s)", errString, e.Info)
	}
	if e.WrappedError != nil {
		errString = fmt.Sprintf("%s (Error: %s)", errString, e.WrappedError.Error())
	}
	return errString
}

func (e *ReadError) Unwrap() error {
	return e.WrappedError
}

func (e *CreateDialError) Error() string {
	return fmt.Sprintf("failed to create connection: %s", e.Message)
}

func (e *CloseDialError) Error() string {
	return "failed to close connection"
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("failed to send request, %s", e.Message)
}

func (e *ServerNotEnable) Error() string {
	return "server is not enabled"
}

func (e *InvalidAddrProvided) Error() string {
	return fmt.Sprintf("a valid address is required for %s service", e.Service)
}
