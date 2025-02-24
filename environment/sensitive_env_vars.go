// Copyright 2024 The Witness Contributors
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

// DefaultSensitiveEnvList return a list of known sensitive environment keys.
//
// Explicit list sourced from https://github.com/Puliczek/awesome-list-of-secrets-in-environment-variables/blob/main/raw_list.txt
func DefaultSensitiveEnvList() map[string]struct{} {
	return map[string]struct{}{

		// Glob pattern list
		"*TOKEN*":      {},
		"*SECRET*":     {},
		"*API_KEY*":    {},
		"*PASSWORD*":   {},
		"*JWT*":        {},
		"*sshKey*":     {},
		"*passphrase*": {},

		// Explicit list
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
