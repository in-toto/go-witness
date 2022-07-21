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

package spiffe

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/testifysec/go-witness/cryptoutil"
	"google.golang.org/grpc"
)

type ErrInvalidSVID string

func (e ErrInvalidSVID) Error() string {
	return fmt.Sprintf("invalid svid: %v", string(e))
}

func Signer(ctx context.Context, socketPath string) (cryptoutil.Signer, error) {
	svidCtx, err := workloadapi.FetchX509Context(ctx, workloadapi.WithAddr(socketPath))
	if err != nil {
		return nil, err
	}

	svid := svidCtx.DefaultSVID()
	if len(svid.Certificates) <= 0 {
		return nil, ErrInvalidSVID("no certificates")
	}

	if svid.PrivateKey == nil {
		return nil, ErrInvalidSVID("no private key")
	}

	return cryptoutil.NewSigner(svid.PrivateKey, cryptoutil.SignWithIntermediates(svid.Certificates[1:]), cryptoutil.SignWithCertificate(svid.Certificates[0]))
}

func DelgatedSigner(ctx context.Context, socketPath string, workloadPath string) (cryptoutil.Signer, error) {
	client, err := getDelgatedClient(ctx, socketPath)
	if err != nil {
		return nil, err
	}

	fmt.Printf("#####: %s", socketPath)

	binPath, err := exec.LookPath(workloadPath)
	if err != nil {
		return nil, err
	}

	hasher := sha256.New()
	s, err := ioutil.ReadFile(binPath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	_, err = hasher.Write(s)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	h := hex.EncodeToString(hasher.Sum(nil))

	selector := types.Selector{
		Type:  "unix",
		Value: fmt.Sprintf("sha256:%s", h),
	}

	selectors := []*types.Selector{
		&selector,
	}

	req := &delegatedidentityv1.SubscribeToX509SVIDsRequest{
		Selectors: selectors,
	}

	stream, err := client.SubscribeToX509SVIDs(ctx, req)
	if err != nil {
		return nil, err
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}

	svids := resp.X509Svids

	svid := svids[0]

	fmt.Printf("### %s", svid.X509Svid)

	chain := svid.X509Svid.CertChain

	privateBytes := svid.X509SvidKey

	key, err := x509.ParsePKCS8PrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}

	var intermediates []*x509.Certificate

	for _, cert := range chain {
		cert, err := x509.ParseCertificate(cert)
		if err != nil {
			return nil, err
		}

		fmt.Printf("\n%s", cert.URIs[0])

		intermediates = append(intermediates, cert)
	}

	return cryptoutil.NewSigner(key, cryptoutil.SignWithIntermediates(intermediates[1:]), cryptoutil.SignWithCertificate(intermediates[0]))

}

func getDelgatedClient(ctx context.Context, socketPath string) (delegatedidentityv1.DelegatedIdentityClient, error) {
	conn, err := grpc.DialContext(ctx, socketPath, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	client := delegatedidentityv1.NewDelegatedIdentityClient(conn)
	return client, nil
}
