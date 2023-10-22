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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/testifysec/go-witness/cryptoutil"
	gomock "go.uber.org/mock/gomock"
)

// TestSpiffeSignerProvider_Signer tests the Signer method of the SpiffeSignerProvider.
func TestSpiffeSignerProvider_Signer(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		socketPath string
		setupMocks func(*MockWorkloadAPI, *MockSignerCreator, *MockX509SVID)
		expectErr  bool
	}{
		{
			name:       "Successful Signer Creation",
			socketPath: "/tmp/spiffe.sock",
			setupMocks: setupSuccessfulCase,
			expectErr:  false,
		},
		{
			name:       "Failed Signer Creation",
			socketPath: "/tmp/spiffe.sock",
			setupMocks: setupFailureCase,
			expectErr:  true,
		},
		{
			name:       "Empty Socket Path",
			socketPath: "",
			setupMocks: setupEmptySocketPathCase,
			expectErr:  true,
		},
		{
			name:       "Invalid Socket Path",
			socketPath: "/invalid/path",
			setupMocks: setupInvalidSocketPathCase,
			expectErr:  true,
		},
	}

	for _, testCase := range testCases {
		tt := testCase // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			workloadAPI := NewMockWorkloadAPI(ctrl)
			signerCreator := NewMockSignerCreator(ctrl)
			x509SVID := NewMockX509SVID(ctrl)

			tt.setupMocks(workloadAPI, signerCreator, x509SVID)

			signerProvider := New(WithWorkloadAPI(workloadAPI), WithSignerCreator(signerCreator), WithSocketPath(tt.socketPath))
			_, err := signerProvider.Signer(context.Background())

			if (err != nil) != tt.expectErr {
				t.Errorf("SpiffeSignerProvider.Signer() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}

// generatePrivateKey generates a private key for testing.
func generatePrivateKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

// generateTestCertificate generates a test certificate for testing.
func generateTestCertificate() []*x509.Certificate {
	return []*x509.Certificate{
		{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Organization: []string{"Test Org"},
				CommonName:   "Test CN",
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Hour),
			IsCA:      false,
		},
	}
}

// setupSuccessfulCase sets up the mocks for the successful case.
func setupSuccessfulCase(workloadAPI *MockWorkloadAPI, signerCreator *MockSignerCreator, x509SVID *MockX509SVID) {
	workloadAPI.EXPECT().FetchX509Context(gomock.Any(), gomock.Any()).Return(x509SVID, nil).Times(1)
	signerCreator.EXPECT().NewSigner(gomock.Any(), gomock.Any()).DoAndReturn(func(privateKey interface{}, opts ...cryptoutil.SignerOption) (cryptoutil.Signer, error) {
		signer, err := cryptoutil.NewSigner(privateKey, opts...)
		return signer, err
	}).Times(1)
	privateKey := generatePrivateKey()
	x509SVID.EXPECT().DefaultSVID().Return(&x509svid.SVID{
		ID:           spiffeid.ID{},
		Certificates: generateTestCertificate(),
		PrivateKey:   privateKey,
	})
}

// setupFailureCase sets up the mocks for the failure case.
func setupFailureCase(workloadAPI *MockWorkloadAPI, signerCreator *MockSignerCreator, x509SVID *MockX509SVID) {
	workloadAPI.EXPECT().FetchX509Context(gomock.Any(), gomock.Any()).Return(x509SVID, nil).Times(1)
	signerCreator.EXPECT().NewSigner(gomock.Any(), gomock.Any()).Return(nil, errors.New("error")).Times(1)
	privateKey := generatePrivateKey()
	x509SVID.EXPECT().DefaultSVID().Return(&x509svid.SVID{
		ID:           spiffeid.ID{},
		Certificates: generateTestCertificate(),
		PrivateKey:   privateKey,
	}).Times(1)
}

// setupEmptySocketPathCase sets up the mocks for the empty socket path case.
func setupEmptySocketPathCase(workloadAPI *MockWorkloadAPI, signerCreator *MockSignerCreator, x509SVID *MockX509SVID) {
	workloadAPI.EXPECT().FetchX509Context(gomock.Any(), gomock.Any()).Times(0)
	signerCreator.EXPECT().NewSigner(gomock.Any(), gomock.Any()).Times(0)
	x509SVID.EXPECT().DefaultSVID().Times(0)
}

// setupInvalidSocketPathCase sets up the mocks for the invalid socket path case.
func setupInvalidSocketPathCase(workloadAPI *MockWorkloadAPI, signerCreator *MockSignerCreator, x509SVID *MockX509SVID) {
	workloadAPI.EXPECT().FetchX509Context(gomock.Any(), gomock.Any()).Return(nil, errors.New("invalid socket path")).Times(1)
	signerCreator.EXPECT().NewSigner(gomock.Any(), gomock.Any()).Times(0)
	x509SVID.EXPECT().DefaultSVID().Times(0)
}
