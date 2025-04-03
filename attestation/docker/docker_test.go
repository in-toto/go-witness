// Copyright 2022 The Witness Contributors
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

package docker

import (
	"crypto"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
	testproducter "github.com/in-toto/go-witness/internal/attestors/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_DockerAttestor(t *testing.T) {
	tests := []struct {
		name         string
		testProducts []string
		validate     func(a *Attestor, err error, name string)
	}{
		{
			name: "ValidMetadataFileWithoutImageDigest",
			testProducts: []string{
				"ewogICJidWlsZHguYnVpbGQucHJvdmVuYW5jZS9saW51eC9hbWQ2NCI6IHsKICAgICJidWlsZFR5cGUiOiAiaHR0cHM6Ly9tb2J5cHJvamVjdC5vcmcvYnVpbGRraXRAdjEiLAogICAgIm1hdGVyaWFscyI6IFsKICAgICAgewogICAgICAgICJ1cmkiOiAicGtnOmRvY2tlci91YnVudHVAbGF0ZXN0P3BsYXRmb3JtPWxpbnV4JTJGYW1kNjQiLAogICAgICAgICJkaWdlc3QiOiB7CiAgICAgICAgICAic2hhMjU2IjogIjcyMjk3ODQ4NDU2ZDVkMzdkMTI2MjYzMDEwOGFiMzA4ZDNlOWVjN2VkMWMzMjg2YTMyZmUwOTg1NjYxOWE3ODIiCiAgICAgICAgfQogICAgICB9CiAgICBdLAogICAgImludm9jYXRpb24iOiB7CiAgICAgICJjb25maWdTb3VyY2UiOiB7fSwKICAgICAgInBhcmFtZXRlcnMiOiB7CiAgICAgICAgImZyb250ZW5kIjogImRvY2tlcmZpbGUudjAiLAogICAgICAgICJsb2NhbHMiOiBbCiAgICAgICAgICB7CiAgICAgICAgICAgICJuYW1lIjogImNvbnRleHQiCiAgICAgICAgICB9LAogICAgICAgICAgewogICAgICAgICAgICAibmFtZSI6ICJkb2NrZXJmaWxlIgogICAgICAgICAgfQogICAgICAgIF0KICAgICAgfSwKICAgICAgImVudmlyb25tZW50IjogewogICAgICAgICJwbGF0Zm9ybSI6ICJsaW51eC9hcm02NCIKICAgICAgfQogICAgfQogIH0sCiAgImJ1aWxkeC5idWlsZC5wcm92ZW5hbmNlL2xpbnV4L2FybTY0IjogewogICAgImJ1aWxkVHlwZSI6ICJodHRwczovL21vYnlwcm9qZWN0Lm9yZy9idWlsZGtpdEB2MSIsCiAgICAibWF0ZXJpYWxzIjogWwogICAgICB7CiAgICAgICAgInVyaSI6ICJwa2c6ZG9ja2VyL3VidW50dUBsYXRlc3Q/cGxhdGZvcm09bGludXglMkZhcm02NCIsCiAgICAgICAgImRpZ2VzdCI6IHsKICAgICAgICAgICJzaGEyNTYiOiAiNzIyOTc4NDg0NTZkNWQzN2QxMjYyNjMwMTA4YWIzMDhkM2U5ZWM3ZWQxYzMyODZhMzJmZTA5ODU2NjE5YTc4MiIKICAgICAgICB9CiAgICAgIH0KICAgIF0sCiAgICAiaW52b2NhdGlvbiI6IHsKICAgICAgImNvbmZpZ1NvdXJjZSI6IHt9LAogICAgICAicGFyYW1ldGVycyI6IHsKICAgICAgICAiZnJvbnRlbmQiOiAiZG9ja2VyZmlsZS52MCIsCiAgICAgICAgImxvY2FscyI6IFsKICAgICAgICAgIHsKICAgICAgICAgICAgIm5hbWUiOiAiY29udGV4dCIKICAgICAgICAgIH0sCiAgICAgICAgICB7CiAgICAgICAgICAgICJuYW1lIjogImRvY2tlcmZpbGUiCiAgICAgICAgICB9CiAgICAgICAgXQogICAgICB9LAogICAgICAiZW52aXJvbm1lbnQiOiB7CiAgICAgICAgInBsYXRmb3JtIjogImxpbnV4L2FybTY0IgogICAgICB9CiAgICB9CiAgfSwKICAiYnVpbGR4LmJ1aWxkLnJlZiI6ICJzdHJhbmdlX2xhbGFuZGUvc3RyYW5nZV9sYWxhbmRlMC9rNzVnemk1OHQ4eW1xemtzbmFkb3dvN3p5Igp9",
			},
			validate: func(a *Attestor, err error, name string) {
				require.Equal(t, a.Products, map[string]DockerProduct{}, "TestName: %s", name)
				require.ErrorContains(t, err, "no products to attest", "TestName: %s", name)
			},
		},
		{
			name: "ValidMetadataFileWithImageDigest",
			testProducts: []string{
				"ewogICJidWlsZHguYnVpbGQucmVmIjogInN0cmFuZ2VfbGFsYW5kZS9zdHJhbmdlX2xhbGFuZGUwL2x0eDE2ZTRybnl1MHhwMDc3N29ybWFybXoiLAogICJjb250YWluZXJpbWFnZS5kZXNjcmlwdG9yIjogewogICAgIm1lZGlhVHlwZSI6ICJhcHBsaWNhdGlvbi92bmQub2NpLmltYWdlLmluZGV4LnYxK2pzb24iLAogICAgImRpZ2VzdCI6ICJzaGEyNTY6NGJlZTAzOTY0MWNlMzAwY2IxZDQ2YTVkMThlMDYxMjVhNzBlYjcwYzM1MWVmNjE2YjZlNDlkNzhiN2RlZjU1ZCIsCiAgICAic2l6ZSI6IDE2MDkKICB9LAogICJjb250YWluZXJpbWFnZS5kaWdlc3QiOiAic2hhMjU2OjRiZWUwMzk2NDFjZTMwMGNiMWQ0NmE1ZDE4ZTA2MTI1YTcwZWI3MGMzNTFlZjYxNmI2ZTQ5ZDc4YjdkZWY1NWQiLAogICJpbWFnZS5uYW1lIjogImdoY3IuaW8vY2hhb3NpbnRoZWNyZC9taWMtdGVzdDpsYXRlc3QiCn0=",
			},
			validate: func(a *Attestor, err error, name string) {
				require.Equal(t, "4bee039641ce300cb1d46a5d18e06125a70eb70c351ef616b6e49d78b7def55d", a.Products["4bee039641ce300cb1d46a5d18e06125a70eb70c351ef616b6e49d78b7def55d"].ImageDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}], "TestName: %s", name)
				require.Equal(t, []string{"ghcr.io/chaosinthecrd/mic-test:latest"}, a.Products["4bee039641ce300cb1d46a5d18e06125a70eb70c351ef616b6e49d78b7def55d"].ImageReferences, "TestName: %s", name)
				require.NoError(t, err, "TestName: %s", name)
			},
		},
		{
			name: "InvalidJsonFile",
			testProducts: []string{
				"ewogICJib21Gb3JtYXQiOiAiQ3ljbG9uZURYIiwKICAic3BlY1ZlcnNpb24iOiAiMS40IiwKICAidmVyc2lvbiI6IDEsCiAgIm1ldGFkYXRhIjogewogICAgImNvbXBvbmVudCI6IHsKICAgICAgImJvbS1yZWYiOiAicGtnOmdvbGFuZy9naXRodWIuY29tL2NoYW9zaW50aGVjcmQvbWljLXRlc3RAKGRldmVsKT90eXBlPW1vZHVsZSIsCiAgICAgICJ0eXBlIjogImFwcGxpY2F0aW9uIiwKICAgICAgIm5hbWUiOiAiZ2l0aHViLmNvbS9jaGFvc2ludGhlY3JkL21pYy10ZXN0IiwKICAgICAgInZlcnNpb24iOiAiKGRldmVsKSIsCiAgICAgICJwdXJsIjogInBrZzpnb2xhbmcvZ2l0aHViLmNvbS9jaGFvc2ludGhlY3JkL21pYy10ZXN0QChkZXZlbCk/dHlwZT1tb2R1bGUiLAogICAgICAiZXh0ZXJuYWxSZWZlcmVuY2VzIjogWwogICAgICAgIHsKICAgICAgICAgICJ1cmwiOiAiaHR0cHM6Ly9naXRodWIuY29tL2NoYW9zaW50aGVjcmQvbWljLXRlc3QiLAogICAgICAgICAgInR5cGUiOiAidmNzIgogICAgICAgIH0KICAgICAgXQogICAgfSwKICAgICJwcm9wZXJ0aWVzIjogWwogICAgICB7CiAgICAgICAgIm5hbWUiOiAiY2R4OmdvbW9kOmJpbmFyeTpuYW1lIiwKICAgICAgICAidmFsdWUiOiAib3V0IgogICAgICB9CiAgICBdCiAgfSwKICAiZGVwZW5kZW5jaWVzIjogWwogICAgewogICAgICAicmVmIjogInBrZzpnb2xhbmcvZ2l0aHViLmNvbS9jaGFvc2ludGhlY3JkL21pYy10ZXN0QChkZXZlbCk/dHlwZT1tb2R1bGUiCiAgICB9CiAgXSwKICAiY29tcG9zaXRpb25zIjogWwogICAgewogICAgICAiYWdncmVnYXRlIjogImNvbXBsZXRlIiwKICAgICAgImRlcGVuZGVuY2llcyI6IFsKICAgICAgICAicGtnOmdvbGFuZy9naXRodWIuY29tL2NoYW9zaW50aGVjcmQvbWljLXRlc3RAKGRldmVsKT90eXBlPW1vZHVsZSIKICAgICAgXQogICAgfSwKICAgIHsKICAgICAgImFnZ3JlZ2F0ZSI6ICJ1bmtub3duIgogICAgfQogIF0KfQo=",
			},
			validate: func(a *Attestor, err error, name string) {
				require.Equal(t, a.Products, map[string]DockerProduct{}, "TestName: %s", name)
				require.Error(t, err, "TestName: %s", name)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := New()

			testProductSet := make(map[string]attestation.Product)
			for _, prod := range tt.testProducts {
				decoded, err := base64.StdEncoding.DecodeString(prod)
				require.NoError(t, err)

				hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

				prodDigest, err := cryptoutil.CalculateDigestSetFromBytes([]byte(decoded), hashes)
				require.NoError(t, err)

				file := SetupTest(t, prod)
				defer os.Remove(file.Name())

				testProductSet[file.Name()] = attestation.Product{
					MimeType: "application/json",
					Digest:   prodDigest,
				}
			}

			tp := testproducter.TestProducter{}
			tp.SetProducts(testProductSet)
			ctx, err := attestation.NewContext("test", []attestation.Attestor{tp, a})
			require.NoError(t, err)

			err = ctx.RunAttestors()
			require.NoError(t, err)

			ca := ctx.CompletedAttestors()
			var dockerErr error
			for _, a := range ca {
				if a.Attestor.Type() == Type {
					dockerErr = a.Error
				}
			}

			tt.validate(a, dockerErr, tt.name)

			for prod := range tp.Products() {
				os.Remove(prod)
			}
		})
	}
}

func SetupTest(t *testing.T, productFileData string) *os.File {
	s := sha1.New()
	s.Write([]byte(productFileData))
	bs := s.Sum(nil)

	file, err := os.CreateTemp("./", fmt.Sprintf("%x.json", bs))
	require.NoError(t, err)

	decoded, err := base64.StdEncoding.DecodeString(productFileData)
	require.NoError(t, err)

	_, err = file.Write([]byte(decoded))
	require.NoError(t, err)

	return file
}

func TestNew(t *testing.T) {
	a := New()

	assert.Equal(t, Name, a.Name())

	assert.Equal(t, Type, a.Type())

	assert.Equal(t, RunType, a.RunType())
}
