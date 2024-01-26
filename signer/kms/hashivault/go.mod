module github.com/in-toto/go-witness/signer/kms/hashivault

replace github.com/in-toto/go-witness => ../../../

go 1.19

require (
	github.com/hashicorp/vault/api v1.9.0
	github.com/in-toto/go-witness v0.0.0-00010101000000-000000000000
	github.com/jellydator/ttlcache/v3 v3.1.1
	github.com/mitchellh/go-homedir v1.1.0
)

require (
	github.com/cenkalti/backoff/v3 v3.2.2 // indirect
	github.com/go-test/deep v1.1.0 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-hclog v1.3.1 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.1 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.7 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/net v0.19.0 // indirect
	golang.org/x/sync v0.4.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/time v0.2.0 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
)
