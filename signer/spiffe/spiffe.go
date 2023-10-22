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

// Package spiffe provides a SPIFFE implementation of the SignerProvider interface.
// It uses the SPIFFE Workload API to fetch SVIDs and uses them to create signers.
package spiffe

import (
	"context"
	"crypto"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/testifysec/go-witness/cryptoutil"
	"github.com/testifysec/go-witness/registry"
	"github.com/testifysec/go-witness/signer"
)

// X509SVID interface represents the X509-SVID. It provides a method to get the default SVID.
type X509SVID interface {
	// DefaultSVID returns the default SVID.
	DefaultSVID() *x509svid.SVID
}

// WorkloadAPI interface represents the Workload API. It provides a method to fetch the X509 context.
type WorkloadAPI interface {
	// FetchX509Context fetches the X509 context.
	FetchX509Context(ctx context.Context, opts ...workloadapi.ClientOption) (X509SVID, error)
}

// SignerCreator interface represents the Signer Creator. It provides a method to create a new signer.
type SignerCreator interface {
	// NewSigner creates a new signer with the provided private key and options.
	NewSigner(privateKey crypto.PrivateKey, opts ...cryptoutil.SignerOption) (cryptoutil.Signer, error)
}

// SpiffeSignerProvider struct represents the Spiffe Signer Provider. It contains the socket path, workload API and signer creator.
type SpiffeSignerProvider struct {
	SocketPath string
	workload   WorkloadAPI
	signer     SignerCreator
}

// ErrInvalidSVID represents an error for invalid SVID. It implements the error interface.
type ErrInvalidSVID string

// Option represents a function that modifies SpiffeSignerProvider. It is used to set the socket path, workload API and signer creator.
type Option func(*SpiffeSignerProvider)

// spiffe struct represents the spiffe and impl. It contains the X509 context.
type spiffe struct {
	x509Context *workloadapi.X509Context
}

// init registers the spiffe signer provider.
func init() {
	signer.Register("spiffe", func() signer.SignerProvider { return New() },
		registry.StringConfigOption(
			"socket-path",
			"Path to the SPIFFE Workload API Socket",
			"",
			func(sp signer.SignerProvider, socketPath string) (signer.SignerProvider, error) {
				ssp, ok := sp.(*SpiffeSignerProvider)
				if !ok {
					return nil, fmt.Errorf("provided signer provider is not a spiffe signer provider")
				}
				WithSocketPath(socketPath)(ssp)
				s := &spiffe{}
				ssp.workload, ssp.signer = s, s
				return ssp, nil
			},
		),
	)
}

// Error method for ErrInvalidSVID. It returns a formatted error message.
func (e ErrInvalidSVID) Error() string {
	return fmt.Sprintf("invalid svid: %v", string(e))
}

// WithSocketPath returns an Option that sets the SocketPath in the SpiffeSignerProvider.
func WithSocketPath(socketPath string) Option {
	return func(ssp *SpiffeSignerProvider) {
		ssp.SocketPath = socketPath
	}
}

// WithWorkloadAPI returns an Option that sets the WorkloadAPI in the SpiffeSignerProvider.
func WithWorkloadAPI(workloadAPI WorkloadAPI) Option {
	return func(ssp *SpiffeSignerProvider) {
		ssp.workload = workloadAPI
	}
}

// WithSignerCreator returns an Option that sets the SignerCreator in the SpiffeSignerProvider.
func WithSignerCreator(signerCreator SignerCreator) Option {
	return func(ssp *SpiffeSignerProvider) {
		ssp.signer = signerCreator
	}
}

// New returns a new SpiffeSignerProvider. It applies the provided options to the SpiffeSignerProvider.
func New(opts ...Option) SpiffeSignerProvider {
	ssp := SpiffeSignerProvider{}
	for _, opt := range opts {
		opt(&ssp)
	}

	return ssp
}

// FetchX509Context fetches the X509 context from the workload API.
func (s *spiffe) FetchX509Context(ctx context.Context, opts ...workloadapi.ClientOption) (X509SVID, error) {
	var err error
	s.x509Context, err = workloadapi.FetchX509Context(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return s.x509Context, nil
}

// DefaultSVID returns the default SVID from the X509 context.
func (s *spiffe) DefaultSVID() *x509svid.SVID {
	return s.x509Context.DefaultSVID()
}

// NewSigner creates a new signer with the provided private key and options.
func (c *spiffe) NewSigner(privateKey crypto.PrivateKey, opts ...cryptoutil.SignerOption) (cryptoutil.Signer, error) {
	return cryptoutil.NewSigner(privateKey, opts...)
}

// Signer returns a cryptoutil.Signer. It fetches the X509 context from the workload API and creates a new signer with the SVID's private key.
func (ssp SpiffeSignerProvider) Signer(ctx context.Context) (cryptoutil.Signer, error) {
	if len(ssp.SocketPath) == 0 {
		return nil, fmt.Errorf("socker path cannot be empty")
	}

	svidCtx, err := ssp.workload.FetchX509Context(ctx, workloadapi.WithAddr(ssp.SocketPath))
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

	return ssp.signer.NewSigner(svid.PrivateKey,
		cryptoutil.SignWithIntermediates(svid.Certificates[1:]), cryptoutil.SignWithCertificate(svid.Certificates[0]))
}
