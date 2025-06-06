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

	archivistaapi "github.com/in-toto/archivista/pkg/api"
	"github.com/in-toto/go-witness/dsse"
)

func (c *Client) Store(ctx context.Context, env dsse.Envelope) (string, error) {
	resp, err := archivistaapi.Store(ctx, c.url, env, c.archivistaRequestOpts()...)
	if err != nil {
		return "", err
	}

	return resp.Gitoid, nil
}
