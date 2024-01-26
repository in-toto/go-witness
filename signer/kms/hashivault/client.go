//
// Copyright 2021 The Sigstore Authors.
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

// Package hashivault implement the interface with hashivault kms service
package hashivault

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/in-toto/go-witness/cryptoutil"
	kms "github.com/in-toto/go-witness/signer/kms"
	"github.com/jellydator/ttlcache/v3"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func init() {
	kms.AddProvider(ReferenceScheme, func(ctx context.Context, ksp *kms.KMSSignerProvider) (cryptoutil.Signer, error) {
		return LoadSignerVerifier(ctx, ksp)
	})
}

type vaultClient struct {
	client                  *vault.Client
	keyPath                 string
	transitSecretEnginePath string
	keyCache                *ttlcache.Cache[string, crypto.PublicKey]
	keyVersion              uint64
}

var (
	errReference   = errors.New("kms specification should be in the format hashivault://<key>")
	referenceRegex = regexp.MustCompile(`^hashivault://(?P<path>\w(([\w-.]+)?\w)?)$`)
	prefixRegex    = regexp.MustCompile("^vault:v[0-9]+:")
)

const (
	vaultV1DataPrefix = "vault:v1:"

	// use a consistent key for cache lookups
	cacheKey = "signer"

	// ReferenceScheme schemes for various KMS services are copied from https://github.com/google/go-cloud/tree/master/secrets
	ReferenceScheme = "hashivault://"
)

// ValidReference returns a non-nil error if the reference string is invalid
func ValidReference(ref string) error {
	if !referenceRegex.MatchString(ref) {
		return errReference
	}
	return nil
}

func parseReference(resourceID string) (keyPath string, err error) {
	i := referenceRegex.SubexpIndex("path")
	v := referenceRegex.FindStringSubmatch(resourceID)
	if len(v) < i+1 {
		err = fmt.Errorf("invalid vault format %q: %w", resourceID, err)
		return
	}
	keyPath = v[i]
	return
}

func newVaultClient(ctx context.Context, ksp *kms.KMSSignerProvider, opts *RPCAuth) (*vaultClient, error) {
	if err := ValidReference(ksp.Reference); err != nil {
		return nil, err
	}

	keyPath, err := parseReference(ksp.Reference)
	if err != nil {
		return nil, err
	}

	client, err := vault.NewClient(&vault.Config{
		Address: opts.Address,
	})
	if err != nil {
		return nil, fmt.Errorf("new vault client: %w", err)
	}

	client.SetToken(opts.Token)

	var keyVersionUint uint64
	if ksp.KeyVersion != "" {
		keyVersionUint, err = strconv.ParseUint(ksp.KeyVersion, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing key version: %w", err)
		}
	}

	hvClient := &vaultClient{
		client:                  client,
		keyPath:                 keyPath,
		transitSecretEnginePath: opts.Path,
		keyCache: ttlcache.New[string, crypto.PublicKey](
			ttlcache.WithDisableTouchOnHit[string, crypto.PublicKey](),
		),
		keyVersion: keyVersionUint,
	}

	return hvClient, nil
}

// NOTE: Not quite sure where to integrate this, but keeping it around for now
func oidcLogin(_ context.Context, address, path, role, token string) (string, error) {
	if address == "" {
		address = os.Getenv("VAULT_ADDR")
	}
	if address == "" {
		return "", errors.New("VAULT_ADDR is not set")
	}
	if path == "" {
		path = "jwt"
	}

	client, err := vault.NewClient(&vault.Config{
		Address: address,
	})
	if err != nil {
		return "", fmt.Errorf("new vault client: %w", err)
	}

	loginData := map[string]interface{}{
		"role": role,
		"jwt":  token,
	}
	fullpath := fmt.Sprintf("auth/%s/login", path)
	resp, err := client.Logical().Write(fullpath, loginData)
	if err != nil {
		return "", fmt.Errorf("vault oidc login: %w", err)
	}
	return resp.TokenID()
}

func (h *vaultClient) fetchPublicKey(_ context.Context) (crypto.PublicKey, error) {
	client := h.client.Logical()

	path := fmt.Sprintf("/%s/keys/%s", h.transitSecretEnginePath, h.keyPath)

	keyResult, err := client.Read(path)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}

	if keyResult == nil {
		return nil, fmt.Errorf("could not read data from transit key path: %s", path)
	}

	keysData, hasKeys := keyResult.Data["keys"]
	latestVersion, hasVersion := keyResult.Data["latest_version"]
	if !hasKeys || !hasVersion {
		return nil, errors.New("failed to read transit key keys: corrupted response")
	}

	keys, ok := keysData.(map[string]interface{})
	if !ok {
		return nil, errors.New("failed to read transit key keys: Invalid keys map")
	}

	keyVersion, ok := latestVersion.(json.Number)
	if !ok {
		return nil, fmt.Errorf("format of 'latest_version' is not json.Number")
	}

	keyData, ok := keys[string(keyVersion)]
	if !ok {
		return nil, errors.New("failed to read transit key keys: corrupted response")
	}

	keyMap, ok := keyData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("could not parse transit key keys data as map[string]interface{}")
	}

	publicKeyPem, ok := keyMap["public_key"]
	if !ok {
		return nil, errors.New("failed to read transit key keys: corrupted response")
	}

	strPublicKeyPem, ok := publicKeyPem.(string)
	if !ok {
		return nil, fmt.Errorf("could not parse public key pem as string")
	}

	return cryptoutils.UnmarshalPEMToPublicKey([]byte(strPublicKeyPem))
}

func (h *vaultClient) public() (crypto.PublicKey, error) {
	var lerr error
	loader := ttlcache.LoaderFunc[string, crypto.PublicKey](
		func(c *ttlcache.Cache[string, crypto.PublicKey], key string) *ttlcache.Item[string, crypto.PublicKey] {
			var pubkey crypto.PublicKey
			pubkey, lerr = h.fetchPublicKey(context.Background())
			if lerr == nil {
				item := c.Set(key, pubkey, 300*time.Second)
				return item
			}
			return nil
		},
	)

	item := h.keyCache.Get(cacheKey, ttlcache.WithLoader[string, crypto.PublicKey](loader))
	if lerr != nil {
		return nil, lerr
	}

	if item == nil {
		return nil, fmt.Errorf("unable to retrieve an item from the cache by the provided key")
	}

	return item.Value(), nil
}

func (h *vaultClient) sign(ctx context.Context, digest []byte, alg crypto.Hash) ([]byte, error) {
	client := h.client.Logical()

	keyVersion := fmt.Sprintf("%d", h.keyVersion)

	if keyVersion != "" {
		if _, err := strconv.ParseUint(keyVersion, 10, 64); err != nil {
			return nil, fmt.Errorf("parsing requested key version: %w", err)
		}
	}

	signResult, err := client.Write(fmt.Sprintf("/%s/sign/%s%s", h.transitSecretEnginePath, h.keyPath, hashString(alg)), map[string]interface{}{
		"input":       base64.StdEncoding.Strict().EncodeToString(digest),
		"prehashed":   alg != crypto.Hash(0),
		"key_version": keyVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("transit: failed to sign payload: %w", err)
	}

	encodedSignature, ok := signResult.Data["signature"]
	if !ok {
		return nil, errors.New("transit: response corrupted in-transit")
	}

	return vaultDecode(encodedSignature, &keyVersion)
}

func (h vaultClient) verify(sig, digest []byte, alg crypto.Hash) error {
	client := h.client.Logical()
	encodedSig := base64.StdEncoding.EncodeToString(sig)

	var vaultDataPrefix string
	vaultDataPrefix = os.Getenv("VAULT_KEY_PREFIX")
	if vaultDataPrefix == "" {
		if h.keyVersion > 0 {
			vaultDataPrefix = fmt.Sprintf("vault:v%d:", h.keyVersion)
		} else {
			vaultDataPrefix = vaultV1DataPrefix
		}
	}

	result, err := client.Write(fmt.Sprintf("/%s/verify/%s/%s", h.transitSecretEnginePath, h.keyPath, hashString(alg)), map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString(digest),
		"prehashed": alg != crypto.Hash(0),
		"signature": fmt.Sprintf("%s%s", vaultDataPrefix, encodedSig),
	})
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	valid, ok := result.Data["valid"]
	if !ok {
		return errors.New("corrupted response")
	}

	isValid, ok := valid.(bool)
	if !ok {
		return fmt.Errorf("received non-bool value from 'valid' key")
	}

	if !isValid {
		return errors.New("failed vault verification")
	}

	return nil
}

// Vault likes to prefix base64 data with a version prefix
func vaultDecode(data interface{}, keyVersionUsed *string) ([]byte, error) {
	encoded, ok := data.(string)
	if !ok {
		return nil, errors.New("received non-string data")
	}

	if keyVersionUsed != nil {
		*keyVersionUsed = prefixRegex.FindString(encoded)
	}
	return base64.StdEncoding.DecodeString(prefixRegex.ReplaceAllString(encoded, ""))
}

func hashString(h crypto.Hash) string {
	var hashStr string
	switch h {
	case crypto.SHA224:
		hashStr = "/sha2-224"
	case crypto.SHA256:
		hashStr = "/sha2-256"
	case crypto.SHA384:
		hashStr = "/sha2-384"
	case crypto.SHA512:
		hashStr = "/sha2-512"
	default:
		hashStr = ""
	}
	return hashStr
}

func (h vaultClient) createKey(typeStr string) (crypto.PublicKey, error) {
	client := h.client.Logical()

	if _, err := client.Write(fmt.Sprintf("/%s/keys/%s", h.transitSecretEnginePath, h.keyPath), map[string]interface{}{
		"type": typeStr,
	}); err != nil {
		return nil, fmt.Errorf("failed to create transit key: %w", err)
	}
	return h.public()
}
