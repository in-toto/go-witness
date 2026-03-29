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

package archivista

import (
	"context"
	"testing"

	"github.com/in-toto/go-witness/dsse"
	"github.com/stretchr/testify/require"
)

func TestClientMethodsWithNilReceiver(t *testing.T) {
	var c *Client

	_, err := c.Download(context.Background(), "sha256:deadbeef")
	require.ErrorIs(t, err, ErrClientNotConfigured)

	_, err = c.SearchGitoids(context.Background(), SearchGitoidVariables{})
	require.ErrorIs(t, err, ErrClientNotConfigured)

	_, err = c.Store(context.Background(), dsse.Envelope{})
	require.ErrorIs(t, err, ErrClientNotConfigured)
}

func TestClientMethodsWithMissingURL(t *testing.T) {
	c := New("")

	_, err := c.Download(context.Background(), "sha256:deadbeef")
	require.ErrorIs(t, err, ErrURLNotConfigured)

	_, err = c.SearchGitoids(context.Background(), SearchGitoidVariables{})
	require.ErrorIs(t, err, ErrURLNotConfigured)

	_, err = c.Store(context.Background(), dsse.Envelope{})
	require.ErrorIs(t, err, ErrURLNotConfigured)
}
