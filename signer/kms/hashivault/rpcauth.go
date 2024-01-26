// Copyright 2023 The Witness Contributors
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

package hashivault

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

// RPCAuth provides credentials for RPC calls, empty fields are ignored
type RPCAuth struct {
	Address string // address is the remote server address, e.g. https://vault:8200
	Path    string // path for the RPC, in vault this is the transit path which default to "transit"
	Token   string // token used for RPC, in vault this is the VAULT_TOKEN value
	OIDC    RPCAuthOIDC
}

// RPCAuthOIDC is used to perform the RPC login using OIDC instead of a fixed token
type RPCAuthOIDC struct {
	Path  string // path defaults to "jwt" for vault
	Role  string // role is required for jwt logins
	Token string // token is a jwt with vault
}

func initRPCOpts() (*RPCAuth, error) {
	opts := &RPCAuth{}

	opts.Address = os.Getenv("VAULT_ADDR")
	if opts.Address == "" {
		return nil, errors.New("VAULT_ADDR is not set")
	}

	opts.Token = os.Getenv("VAULT_TOKEN")
	if opts.Token == "" {
		log.Printf("VAULT_TOKEN is not set, trying to read token from file at path ~/.vault-token")
		homeDir, err := homedir.Dir()
		if err != nil {
			return nil, fmt.Errorf("get home directory: %w", err)
		}

		tokenFromFile, err := os.ReadFile(filepath.Join(homeDir, ".vault-token"))
		if err != nil {
			return nil, fmt.Errorf("read .vault-token file: %w", err)
		}

		opts.Token = string(tokenFromFile)
		if opts.Token == "" {
			return nil, errors.New("failed to get token from ~/.vault-token")
		}
	}

	opts.Path = os.Getenv("TRANSIT_SECRET_ENGINE_PATH")
	if opts.Path == "" {
		opts.Path = "transit"
	}

	return opts, nil
}
