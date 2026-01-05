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
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GRPCDialWithTimeout establishes a plaintext gRPC connection to the specified target
// with a timeout. This is the foundational function for gRPC-based fingerprinting.
//
// Parameters:
//   - target: Address to connect to (e.g., "localhost:19530")
//   - timeout: Connection timeout duration
//
// Returns:
//   - *grpc.ClientConn: Established connection
//   - error: Connection error if failed
func GRPCDialWithTimeout(target string, timeout time.Duration) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Use insecure credentials for fingerprinting (we're not authenticating)
	conn, err := grpc.DialContext(ctx, target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(), // Block until connection established or timeout
	)
	if err != nil {
		return nil, fmt.Errorf("grpc dial failed: %w", err)
	}

	return conn, nil
}

// GRPCInvokeUnary invokes a unary gRPC method with raw byte marshaling.
// This is useful when you don't want to import full proto definitions.
//
// Parameters:
//   - conn: Established gRPC connection
//   - method: Full method name (e.g., "/milvus.proto.milvus.MilvusService/GetVersion")
//   - request: Marshaled request bytes (can be empty for methods with no input)
//   - timeout: RPC timeout duration
//
// Returns:
//   - []byte: Marshaled response bytes
//   - error: RPC error if failed
func GRPCInvokeUnary(conn *grpc.ClientConn, method string, request []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var response []byte
	err := conn.Invoke(ctx, method, request, &response)
	if err != nil {
		return nil, fmt.Errorf("grpc invoke failed: %w", err)
	}

	return response, nil
}
