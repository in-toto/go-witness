// Copyright 2021 The Witness Contributors
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

package environment

import (
	"strings"

	"github.com/gobwas/glob"
	"github.com/in-toto/go-witness/log"
)

// sourced from https://github.com/Puliczek/awesome-list-of-secrets-in-environment-variables/blob/main/raw_list.txt
func DefaultBlockList() map[string]struct{} {
	return map[string]struct{}{
		"AWS_ACCESS_KEY_ID":              {},
		"AWS_SECRET_ACCESS_KEY":          {},
		"AMAZON_AWS_ACCESS_KEY_ID":       {},
		"AMAZON_AWS_SECRET_ACCESS_KEY":   {},
		"ALGOLIA_API_KEY":                {},
		"AZURE_CLIENT_ID":                {},
		"AZURE_CLIENT_SECRET":            {},
		"AZURE_USERNAME":                 {},
		"AZURE_PASSWORD":                 {},
		"MSI_ENDPOINT":                   {},
		"MSI_SECRET":                     {},
		"binance_api":                    {},
		"binance_secret":                 {},
		"BITTREX_API_KEY":                {},
		"BITTREX_API_SECRET":             {},
		"CF_PASSWORD":                    {},
		"CF_USERNAME":                    {},
		"CODECLIMATE_REPO_TOKEN":         {},
		"COVERALLS_REPO_TOKEN":           {},
		"CIRCLE_TOKEN":                   {},
		"DIGITALOCEAN_ACCESS_TOKEN":      {},
		"DOCKER_EMAIL":                   {},
		"DOCKER_PASSWORD":                {},
		"DOCKER_USERNAME":                {},
		"DOCKERHUB_PASSWORD":             {},
		"FACEBOOK_APP_ID":                {},
		"FACEBOOK_APP_SECRET":            {},
		"FACEBOOK_ACCESS_TOKEN":          {},
		"FIREBASE_TOKEN":                 {},
		"FOSSA_API_KEY":                  {},
		"GH_TOKEN":                       {},
		"GH_ENTERPRISE_TOKEN":            {},
		"GOOGLE_APPLICATION_CREDENTIALS": {},
		"GOOGLE_API_KEY":                 {},
		"CI_DEPLOY_USER":                 {},
		"CI_DEPLOY_PASSWORD":             {},
		"GITLAB_USER_LOGIN":              {},
		"CI_JOB_JWT":                     {},
		"CI_JOB_JWT_V2":                  {},
		"CI_JOB_TOKEN":                   {},
		"HEROKU_API_KEY":                 {},
		"HEROKU_API_USER":                {},
		"MAILGUN_API_KEY":                {},
		"MCLI_PRIVATE_API_KEY":           {},
		"MCLI_PUBLIC_API_KEY":            {},
		"NGROK_TOKEN":                    {},
		"NGROK_AUTH_TOKEN":               {},
		"NPM_AUTH_TOKEN":                 {},
		"OKTA_CLIENT_ORGURL":             {},
		"OKTA_CLIENT_TOKEN":              {},
		"OKTA_OAUTH2_CLIENTSECRET":       {},
		"OKTA_OAUTH2_CLIENTID":           {},
		"OKTA_AUTHN_GROUPID":             {},
		"OS_USERNAME":                    {},
		"OS_PASSWORD":                    {},
		"PERCY_TOKEN":                    {},
		"SAUCE_ACCESS_KEY":               {},
		"SAUCE_USERNAME":                 {},
		"SENTRY_AUTH_TOKEN":              {},
		"SLACK_TOKEN":                    {},
		"SNYK_TOKEN":                     {},
		"square_access_token":            {},
		"square_oauth_secret":            {},
		"STRIPE_API_KEY":                 {},
		"STRIPE_DEVICE_NAME":             {},
		"SURGE_TOKEN":                    {},
		"SURGE_LOGIN":                    {},
		"TWILIO_ACCOUNT_SID":             {},
		"CONSUMER_KEY":                   {},
		"CONSUMER_SECRET":                {},
		"TRAVIS_SUDO":                    {},
		"TRAVIS_OS_NAME":                 {},
		"TRAVIS_SECURE_ENV_VARS":         {},
		"VAULT_TOKEN":                    {},
		"VAULT_CLIENT_KEY":               {},
		"TOKEN":                          {},
		"VULTR_ACCESS":                   {},
		"VULTR_SECRET":                   {},
		"ACTIONS_RUNTIME_TOKEN":          {},
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": {},
	}
}

// FilterEnvironmentArray expects an array of strings representing environment variables.  Each element of the array is expected to be in the format of "KEY=VALUE".
// blockList is the list of elements to filter from variables, and for each element of variables that does not appear in the blockList onAllowed will be called.
func FilterEnvironmentArray(variables []string, blockList map[string]struct{}, onAllowed func(key, val, orig string)) {
	filterGlobList := []glob.Glob{}

	for k := range blockList {
		if strings.Contains(k, "*") {
			filterGlobCompiled, err := glob.Compile(k)
			if err != nil {
				log.Errorf("obfuscate glob pattern could not be interpreted: %w", err)
			}

			filterGlobList = append(filterGlobList, filterGlobCompiled)
		}
	}

	for _, v := range variables {
		key, val := splitVariable(v)
		filterOut := false

		if _, inBlockList := blockList[key]; inBlockList {
			filterOut = true
		}

		for _, glob := range filterGlobList {
			if glob.Match(key) {
				filterOut = true
				break
			}
		}

		if !filterOut {
			onAllowed(key, val, v)
		}
	}
}
