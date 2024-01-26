module github.com/in-toto/go-witness/signer/kms/hashivault

replace github.com/in-toto/go-witness => ../../../

go 1.19

require (
	github.com/hashicorp/vault/api v1.9.0
	github.com/in-toto/go-witness v0.0.0-00010101000000-000000000000
	github.com/jellydator/ttlcache/v3 v3.1.1
	github.com/mitchellh/go-homedir v1.1.0
	github.com/sigstore/sigstore v1.5.2
)

require (
	github.com/cenkalti/backoff/v3 v3.2.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-containerregistry v0.13.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.1 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.7 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/letsencrypt/boulder v0.0.0-20221109233200-85aa52084eaf // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/theupdateframework/go-tuf v0.5.2-0.20220930112810-3890c1e7ace4 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/net v0.19.0 // indirect
	golang.org/x/sync v0.4.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/term v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/time v0.2.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231016165738-49dd2c1f3d0b // indirect
	google.golang.org/grpc v1.60.1 // indirect
	google.golang.org/protobuf v1.32.0 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
