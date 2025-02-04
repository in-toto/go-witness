package k8smanifest

import (
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/pkg/oci/remote"
)

func DigestForRef(reference string) (string, error) {
	if strings.Contains(reference, "@sha256:") {
		return "", nil
	}

	ref, err := name.ParseReference(reference)
	if err != nil {
		return "", err
	}

	nref, err := remote.ResolveDigest(ref)
	if err != nil {
		return "", err
	}

	return nref.DigestStr(), nil
}
