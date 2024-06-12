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
	"fmt"

	"github.com/in-toto/go-witness/registry"
	"github.com/in-toto/go-witness/signer"
	"github.com/in-toto/go-witness/signer/kms"
)

const (
	defaultTransitSecretEnginePath        = "transit"
	defaultKeyVersion              uint64 = 0
	defaultAuthMethod                     = "token"
	defaultKubernetesSATokenPath          = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultKubernetesAuthMountPath        = "kubernetes"
)

type Option func(*clientOptions)

type clientOptions struct {
	addr                    string
	transitSecretEnginePath string
	keyVersion              int32
	keyPath                 string
	authMethod              string
	tokenPath               string
	kubernetesSaTokenPath   string
	role                    string
	kubernetesMountPath     string
}

func (*clientOptions) ProviderName() string {
	return providerName
}

func (hv *clientOptions) Init() []registry.Configurer {
	return []registry.Configurer{
		registry.StringConfigOption(
			"addr",
			"Address of the vault instance to connect to. Defaults to the environment variable VAULT_ADDR if unset",
			"",
			func(sp signer.SignerProvider, addr string) (signer.SignerProvider, error) {
				ksp, ok := sp.(*kms.KMSSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a kms signer provider")
				}

				co, ok := ksp.Options[providerName].(*clientOptions)
				if !ok {
					return sp, fmt.Errorf("failed to get hashivault client options from kms signer provider")
				}

				WithAddr(addr)(co)
				return ksp, nil
			},
		),
		registry.StringConfigOption(
			"token-file",
			"File to read the Vault token from for token auth. Token will be read from the environment variable VAULT_TOKEN if unset",
			"",
			func(sp signer.SignerProvider, tokenFile string) (signer.SignerProvider, error) {
				ksp, ok := sp.(*kms.KMSSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a kms signer provider")
				}

				co, ok := ksp.Options[providerName].(*clientOptions)
				if !ok {
					return sp, fmt.Errorf("failed to get hashivault client options from kms signer provider")
				}

				WithTokenFile(tokenFile)(co)
				return ksp, nil
			},
		),
		registry.StringConfigOption(
			"transit-secret-engine-path",
			"Path to the Vault Transit secret engine to use",
			defaultTransitSecretEnginePath,
			func(sp signer.SignerProvider, transitSecretEnginePath string) (signer.SignerProvider, error) {
				ksp, ok := sp.(*kms.KMSSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a kms signer provider")
				}

				co, ok := ksp.Options[providerName].(*clientOptions)
				if !ok {
					return sp, fmt.Errorf("failed to get hashivault client options from kms signer provider")
				}

				WithTransitSecretEnginePath(transitSecretEnginePath)(co)
				return ksp, nil
			},
		),
		registry.StringConfigOption(
			"auth-method",
			"Method to use to authenticate with Vault. Currently supported methods are token and kubernetes",
			defaultAuthMethod,
			func(sp signer.SignerProvider, authMethod string) (signer.SignerProvider, error) {
				ksp, ok := sp.(*kms.KMSSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a kms signer provider")
				}

				co, ok := ksp.Options[providerName].(*clientOptions)
				if !ok {
					return sp, fmt.Errorf("failed to get hashivault client options from kms signer provider")
				}

				WithAuthMethod(authMethod)(co)
				return ksp, nil

			},
		),
		registry.StringConfigOption(
			"kubernetes-service-account-token-path",
			"Path to the file containing the token for the kubernetes service account when using the kubernetes auth method",
			defaultKubernetesSATokenPath,
			func(sp signer.SignerProvider, saTokenPath string) (signer.SignerProvider, error) {
				ksp, ok := sp.(*kms.KMSSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a kms signer provider")
				}

				co, ok := ksp.Options[providerName].(*clientOptions)
				if !ok {
					return sp, fmt.Errorf("failed to get hashivault client options from kms signer provider")
				}

				WithKubernetesServiceAccountTokenPath(saTokenPath)(co)
				return ksp, nil

			},
		),
		registry.StringConfigOption(
			"role",
			"Role name to use when authenticating with the kubernetes auth method",
			"",
			func(sp signer.SignerProvider, role string) (signer.SignerProvider, error) {
				ksp, ok := sp.(*kms.KMSSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a kms signer provider")
				}

				co, ok := ksp.Options[providerName].(*clientOptions)
				if !ok {
					return sp, fmt.Errorf("failed to get hashivault client options from kms signer provider")
				}

				WithRole(role)(co)
				return ksp, nil

			},
		),
		registry.StringConfigOption(
			"kubernetes-auth-mount-path",
			"Path where the kubernetes auth endpoint is mounted on the vault server",
			defaultKubernetesAuthMountPath,
			func(sp signer.SignerProvider, kubernetesAuthMountPath string) (signer.SignerProvider, error) {
				ksp, ok := sp.(*kms.KMSSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a kms signer provider")
				}

				co, ok := ksp.Options[providerName].(*clientOptions)
				if !ok {
					return sp, fmt.Errorf("failed to get hashivault client options from kms signer provider")
				}

				WithKubernetesAuthMountPath(kubernetesAuthMountPath)(co)
				return ksp, nil

			},
		),
	}

}

func WithAddr(addr string) Option {
	return func(hco *clientOptions) {
		hco.addr = addr
	}
}

func WithTokenFile(tokenFile string) Option {
	return func(hco *clientOptions) {
		hco.tokenPath = tokenFile
	}
}

func WithTransitSecretEnginePath(transitSecretEnginePath string) Option {
	return func(hco *clientOptions) {
		hco.transitSecretEnginePath = transitSecretEnginePath
	}
}

func WithAuthMethod(authMethod string) Option {
	return func(hco *clientOptions) {
		hco.authMethod = authMethod
	}
}

func WithKubernetesServiceAccountTokenPath(saTokenPath string) Option {
	return func(hco *clientOptions) {
		hco.kubernetesSaTokenPath = saTokenPath
	}
}

func WithRole(role string) Option {
	return func(hco *clientOptions) {
		hco.role = role
	}
}

func WithKubernetesAuthMountPath(kubernetesAuthMountPath string) Option {
	return func(hco *clientOptions) {
		hco.kubernetesMountPath = kubernetesAuthMountPath
	}
}
