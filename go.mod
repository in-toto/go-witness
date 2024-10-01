module github.com/in-toto/go-witness

go 1.22.5

require (
	cloud.google.com/go/kms v1.15.9
	github.com/CycloneDX/cyclonedx-go v0.9.1
	github.com/aws/aws-sdk-go-v2/config v1.27.39
	github.com/aws/aws-sdk-go-v2/service/kms v1.31.3
	github.com/digitorus/pkcs7 v0.0.0-20230818184609-3a137a874352
	github.com/digitorus/timestamp v0.0.0-20231217203849-220c5c2851b7
	github.com/edwarnicke/gitoid v0.0.0-20220710194850-1be5bfda1f9d
	github.com/fkautz/omnitrail-go v0.0.0-20230808061951-37d34c23539d
	github.com/gabriel-vasile/mimetype v1.4.5
	github.com/go-git/go-git/v5 v5.11.0
	github.com/go-jose/go-jose/v3 v3.0.3
	github.com/in-toto/archivista v0.5.4
	github.com/in-toto/attestation v1.0.2
	github.com/invopop/jsonschema v0.12.0
	github.com/jellydator/ttlcache/v3 v3.2.1
	github.com/mattn/go-isatty v0.0.20
	github.com/mitchellh/go-homedir v1.1.0
	github.com/open-policy-agent/opa v0.68.0
	github.com/owenrumney/go-sarif v1.1.1
	github.com/sigstore/fulcio v1.4.5
	github.com/spdx/tools-golang v0.5.5
	github.com/spiffe/go-spiffe/v2 v2.1.7
	github.com/stretchr/testify v1.9.0
	go.step.sm/crypto v0.44.8
	golang.org/x/mod v0.18.0
	golang.org/x/sys v0.24.0
	google.golang.org/api v0.177.0
	google.golang.org/grpc v1.66.0
	gopkg.in/go-jose/go-jose.v2 v2.6.3
	k8s.io/apimachinery v0.30.5
)

require (
	cloud.google.com/go/auth v0.3.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.2 // indirect
	cloud.google.com/go/compute/metadata v0.3.0 // indirect
	cloud.google.com/go/iam v1.1.7 // indirect
	dario.cat/mergo v1.0.0 // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/agnivade/levenshtein v1.1.1 // indirect
	github.com/anchore/go-struct-converter v0.0.0-20221118182256-c68fdcfa2092 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/aws/aws-sdk-go-v2 v1.31.0 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.37 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.14 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.18 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.18 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.20 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.23.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.27.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.31.3 // indirect
	github.com/aws/smithy-go v1.21.0 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/buger/jsonparser v1.1.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/coreos/go-oidc/v3 v3.11.0 // indirect
	github.com/cyphar/filepath-securejoin v0.2.4 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-jose/go-jose/v4 v4.0.2 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/flatbuffers v2.0.8+incompatible // indirect
	github.com/google/go-containerregistry v0.20.2 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/s2a-go v0.1.7 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.2 // indirect
	github.com/googleapis/gax-go/v2 v2.12.3 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.20.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/letsencrypt/boulder v0.0.0-20240620165639-de9c06129bec // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/omnibor/omnibor-go v0.0.0-20230521145532-a77de61a16cd // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/package-url/packageurl-go v0.1.1 // indirect
	github.com/pjbgf/sha1cd v0.3.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.20.2 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.8.0 // indirect
	github.com/segmentio/ksuid v1.0.4 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/skeema/knownhosts v1.2.1 // indirect
	github.com/skratchdot/open-golang v0.0.0-20200116055534-eef842397966 // indirect
	github.com/tchap/go-patricia/v2 v2.3.1 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	github.com/wk8/go-ordered-map/v2 v2.1.8 // indirect
	github.com/zclconf/go-cty v1.14.4 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.52.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.53.0 // indirect
	go.opentelemetry.io/otel v1.28.0 // indirect
	go.opentelemetry.io/otel/metric v1.28.0 // indirect
	go.opentelemetry.io/otel/sdk v1.28.0 // indirect
	go.opentelemetry.io/otel/trace v1.28.0 // indirect
	golang.org/x/oauth2 v0.22.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/time v0.6.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240701130421-f6361c86f094 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240701130421-f6361c86f094 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/klog/v2 v2.120.1 // indirect
	k8s.io/utils v0.0.0-20240423183400-0849a56e8f22 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/ProtonMail/go-crypto v1.0.0 // indirect
	github.com/aws/aws-sdk-go v1.50.38
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.5.0 // indirect
	github.com/gobwas/glob v0.2.3
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/openvex/go-vex v0.2.5
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/sergi/go-diff v1.3.1 // indirect
	github.com/sigstore/sigstore v1.8.9
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/yashtewari/glob-intersection v0.2.0 // indirect
	github.com/zeebo/errs v1.3.0 // indirect
	golang.org/x/crypto v0.26.0 // indirect
	golang.org/x/exp v0.0.0-20240416160154-fe59bbe5cc7f
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/term v0.23.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	google.golang.org/genproto v0.0.0-20240401170217-c3f982113cda // indirect
	google.golang.org/protobuf v1.34.2
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/sigstore/rekor => github.com/testifysec/rekor v0.4.0-dsse-intermediates-2

replace github.com/gin-gonic/gin v1.5.0 => github.com/gin-gonic/gin v1.7.7
