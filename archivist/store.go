// Copyright 2022 The Witness Contributors
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

package archivist

import (
	"context"

	"github.com/testifysec/archivist-api/pkg/api/archivist"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func (c *Client) Store(ctx context.Context, signedBytes []byte) (string, error) {
	conn, err := grpc.Dial(c.grpcUrl, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return "", err
	}

	client := archivist.NewCollectorClient(conn)
	size := len(signedBytes)
	chunk := &archivist.Chunk{}
	stream, err := client.Store(ctx)
	if err != nil {
		return "", err
	}

	for curr := 0; curr < size; curr += c.grpcChunkSize {
		var chunkBytes []byte
		if curr+c.grpcChunkSize >= size {
			chunkBytes = signedBytes[curr:]
		} else {
			chunkBytes = signedBytes[curr : curr+c.grpcChunkSize]
		}

		chunk.Chunk = chunkBytes
		if err := stream.Send(chunk); err != nil {
			return "", err
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		return "", err
	}

	return resp.GetGitoid(), nil
}
