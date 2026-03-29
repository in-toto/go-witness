// Copyright 2024 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hashivault

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"

	vault "github.com/hashicorp/vault/api"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/signer/kms"
)

func init() {
	kms.AddProvider(ReferenceScheme, &clientOptions{}, func(ctx context.Context, ksp *kms.KMSSignerProvider) (cryptoutil.Signer, error) {
		return LoadSignerVerifier(ctx, ksp)
	})
}

const (
	ReferenceScheme = "hashivault://"
	providerName    = "kms-hashivault"
)

var (
	errReference   = errors.New("kms specification should be in the format hashivault://<key>")
	referenceRegex = regexp.MustCompile(`^hashivault://(?P<path>\w(([\w-.]+)?\w)?)$`)
)

func ValidReference(ref string) error {
	if !referenceRegex.MatchString(ref) {
		return errReference
	}

	return nil
}

type client struct {
	client                   *vault.Client
	keyPath                  string
	transitSecretsEnginePath string
	keyVersion               int32

	authMethod              string
	tokenPath               string
	kubernetesAuthMountPath string
	kubernetesSaTokenPath   string
	role                    string
}

func newClient(ctx context.Context, opts *clientOptions) (*client, error) {
	vaultConf := vault.DefaultConfig()
	if len(opts.addr) > 0 {
		vaultConf.Address = opts.addr
	}

	vaultClient, err := vault.NewClient(vaultConf)
	if err != nil {
		return nil, fmt.Errorf("could not create vault client: %w", err)
	}

	c := &client{
		client:                   vaultClient,
		keyPath:                  opts.keyPath,
		transitSecretsEnginePath: opts.transitSecretEnginePath,
		keyVersion:               opts.keyVersion,
		authMethod:               opts.authMethod,
		tokenPath:                opts.tokenPath,
		kubernetesAuthMountPath:  opts.kubernetesMountPath,
		kubernetesSaTokenPath:    opts.kubernetesSaTokenPath,
		role:                     opts.role,
	}

	authInfo, err := c.login(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not authenticate with vault: %w", err)
	}

	if authInfo != nil {
		go c.periodicallyRenewAuth(ctx, authInfo)
	}

	return c, err
}

func (c *client) sign(ctx context.Context, digest []byte, hashFunc crypto.Hash) ([]byte, error) {
	hashStr, ok := supportedHashesToString[hashFunc]
	if !ok {
		return nil, fmt.Errorf("unsupported hash algorithm: %v", hashFunc.String())
	}

	path := fmt.Sprintf("/%v/sign/%v/%v", c.transitSecretsEnginePath, c.keyPath, hashStr)
	resp, err := c.client.Logical().WriteWithContext(
		ctx,
		path,
		map[string]interface{}{
			"input":               base64.StdEncoding.Strict().EncodeToString(digest),
			"prehashed":           true,
			"key_version":         c.keyVersion,
			"signature_algorithm": "pkcs1v15",
		})

	if err != nil {
		return nil, fmt.Errorf("could not sign: %w", err)
	}

	signature, ok := resp.Data["signature"]
	if !ok {
		return nil, fmt.Errorf("no signature in response: %w", err)
	}

	sigStr, ok := signature.(string)
	if !ok {
		return nil, fmt.Errorf("invalid signature in response")
	}

	return []byte(sigStr), nil
}

func (c *client) verify(ctx context.Context, r io.Reader, sig []byte, hashFunc crypto.Hash) error {
	hashStr, ok := supportedHashesToString[hashFunc]
	if !ok {
		return fmt.Errorf("unsupported hash algorithm: %v", hashFunc.String())
	}

	digest, err := cryptoutil.Digest(r, hashFunc)
	if err != nil {
		return fmt.Errorf("could not calculate digest: %w", err)
	}

	resp, err := c.client.Logical().WriteWithContext(
		ctx,
		fmt.Sprintf("/%v/verify/%v/%v", c.transitSecretsEnginePath, c.keyPath, hashStr),
		map[string]interface{}{
			"signature_algorithm": "pkcs1v15",
			"input":               base64.StdEncoding.Strict().EncodeToString(digest),
			"signature":           string(sig),
			"prehashed":           true,
		},
	)

	if err != nil {
		return fmt.Errorf("could not verify: %w", err)
	}

	valid, ok := resp.Data["valid"]
	if !ok {
		return fmt.Errorf("invalid response")
	}

	validBool, ok := valid.(bool)
	if !ok {
		return fmt.Errorf("expected valid to be bool but is %T", valid)
	}

	if !validBool {
		return fmt.Errorf("failed verification")
	}

	return nil
}

func (c *client) getPublicKeyBytes(ctx context.Context) ([]byte, error) {
	resp, err := c.client.Logical().ReadWithContext(
		ctx,
		fmt.Sprintf("/%v/keys/%v", c.transitSecretsEnginePath, c.keyPath),
	)

	if err != nil {
		return nil, fmt.Errorf("could not read key: %w", err)
	}

	keyVersion := strconv.FormatInt(int64(c.keyVersion), 10)
	if keyVersion == "0" {
		latestVersion, ok := resp.Data["latest_version"]
		if !ok {
			return nil, fmt.Errorf("latest key version not in response")
		}

		latestVersionNum, ok := latestVersion.(json.Number)
		if !ok {
			return nil, fmt.Errorf("latest version not a number")
		}

		keyVersion = latestVersionNum.String()
	}

	keys, ok := resp.Data["keys"]
	if !ok {
		return nil, fmt.Errorf("no keys in response")
	}

	keysMap, ok := keys.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected keys value in response")
	}

	keyInfo, ok := keysMap[keyVersion]
	if !ok {
		return nil, fmt.Errorf("could not find key with version %v", keyVersion)
	}

	keyMap, ok := keyInfo.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected key data format in response")
	}

	publicKey, ok := keyMap["public_key"]
	if !ok {
		return nil, fmt.Errorf("public key not in key data")
	}

	publicKeyStr, ok := publicKey.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected public key data in response")
	}

	return []byte(publicKeyStr), nil
}
