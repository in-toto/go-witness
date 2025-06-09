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
	"net/http"

	"github.com/in-toto/archivista/pkg/api"
)

type Client struct {
	url     string      `json:"url" jsonschema:"title=URL,description=Archivista server URL,example=https://archivista.example.com"`
	headers http.Header `json:"headers,omitempty" jsonschema:"title=Headers,description=Custom HTTP headers to include in requests"`
}

type Option func(*Client)

func WithHeaders(h http.Header) Option {
	return func(c *Client) {
		if h != nil {
			c.headers = h
		}
	}
}

func New(url string, opts ...Option) *Client {
	c := &Client{
		url: url,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}

		opt(c)
	}

	return c
}

func (c *Client) archivistaRequestOpts() []api.RequestOption {
	opts := make([]api.RequestOption, 0)
	if c.headers != nil {
		opts = append(opts, api.WithHeaders(c.headers))
	}

	return opts
}
