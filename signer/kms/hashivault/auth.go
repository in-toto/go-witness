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
	"fmt"
	"os"
	"strings"

	vault "github.com/hashicorp/vault/api"
	k8sAuth "github.com/hashicorp/vault/api/auth/kubernetes"
	"github.com/in-toto/go-witness/log"
)

type contextDoneErr struct{}

func (contextDoneErr) Error() string {
	return "context done"
}

type needLoginErr struct {
	watcherErr error
}

func (e needLoginErr) Error() string {
	return fmt.Sprintf("need login: %v", e.watcherErr)
}

// login will authenticate with vault with the configured auth method
func (c *client) login(ctx context.Context) (*vault.Secret, error) {
	if c.client == nil {
		return nil, fmt.Errorf("vault client cannot be nil for login")
	}

	switch strings.ToLower(c.authMethod) {
	case "token":
		token := ""
		if len(c.tokenPath) > 0 {
			tokenBytes, err := os.ReadFile(c.tokenPath)
			if err != nil {
				return nil, fmt.Errorf("could not read vault token file: %w", err)
			}

			token = string(tokenBytes)
		}

		if len(token) > 0 {
			c.client.SetToken(token)
		}

		// token based auth can't be refreshed, so no secret to return
		return nil, nil

	case "kubernetes":
		authMethod, err := k8sAuth.NewKubernetesAuth(
			c.role,
			k8sAuth.WithServiceAccountTokenPath(c.kubernetesSaTokenPath),
			k8sAuth.WithMountPath(c.kubernetesAuthMountPath),
		)

		if err != nil {
			return nil, fmt.Errorf("could not create kubernetes auth method: %w", err)
		}

		authInfo, err := c.client.Auth().Login(ctx, authMethod)
		if err != nil {
			return nil, fmt.Errorf("could not login with kubernetes auth method: %w", err)
		}

		return authInfo, nil

	default:
		return nil, fmt.Errorf("unknown auth method: %v", c.authMethod)
	}
}

// periodicallyRenewAuth will start a watcher that will attempt to periodically renew vault's auth token.
// if the auth token's refresh lease is up, it will attempt to re-login entirely.
func (c *client) periodicallyRenewAuth(ctx context.Context, authInfo *vault.Secret) {
	if authInfo == nil {
		log.Debugf("can't refresh a nil vault secret")
		return
	}

	currentAuthInfo := authInfo
	for {
		err := c.renewAuth(ctx, currentAuthInfo)
		// if the context signed on it's Done channel, we're cleaning up, bail out
		if _, ok := err.(contextDoneErr); ok {
			return
		} else if _, ok := err.(needLoginErr); ok {
			authInfo, err := c.login(ctx)
			if err != nil {
				log.Errorf("could not re-login to vault: %v", err)
				return
			}

			currentAuthInfo = authInfo
		} else if err != nil {
			log.Errorf("could not renew auth token: %v", err)
			return
		}
	}
}

// renewAuth is the meat of periodicallyRenewAuth. it creates the vault lifetime watcher and refreshes
// the current auth token as long as it has lease duration available.
func (c *client) renewAuth(ctx context.Context, authInfo *vault.Secret) error {
	watcher, err := c.client.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
		Secret: authInfo,
	})

	if err != nil {
		return fmt.Errorf("could not create vault token watcher: %w", err)
	}

	go watcher.Start()
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return contextDoneErr{}

		// if the watcher signals on it's done channel it means it either failed to refresh the current
		// token's lease, or the token's remaining lease duration is too short and we need to re-login.
		case err := <-watcher.DoneCh():
			return needLoginErr{watcherErr: err}

		case info := <-watcher.RenewCh():
			log.Debugf("renewed vault auth token, remaining lease duration: %d", info.Secret.LeaseDuration)
		}
	}
}
