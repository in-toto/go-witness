// Copyright 2026 The Witness Contributors
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

//go:build linux && !android && (amd64 || arm64)

package pkcs11

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

const fakeTokenLabel = "fake token"

// fakeObject is an object on the fake token: attribute values by type.
type fakeObject map[ckULong][]byte

// newFakeModule returns a module whose functions are Go closures over objects
// instead of C functions from a loaded library, so that the key lookup can be
// tested without a token. The handle of an object is its index plus one.
func newFakeModule(objects []fakeObject) *module {
	var found []ckULong
	return &module{
		getSlotList: func(_ uint8, slots *ckULong, count *ckULong) ckULong {
			if slots != nil {
				*slots = 1
			}
			*count = 1
			return ckrOK
		},
		getTokenInfo: func(_ ckULong, info *ckTokenInfo) ckULong {
			copy(info.label[:], fmt.Sprintf("%-32s", fakeTokenLabel))
			return ckrOK
		},
		openSession: func(_, _ ckULong, _ unsafe.Pointer, _ uintptr, session *ckULong) ckULong {
			*session = 1
			return ckrOK
		},
		login: func(_, _ ckULong, _ *byte, _ ckULong) ckULong { return ckrOK },
		findObjectsInit: func(_ ckULong, tmpl *ckAttribute, count ckULong) ckULong {
			found = nil
			for i, object := range objects {
				matches := true
				for _, attr := range unsafe.Slice(tmpl, count) {
					want := unsafe.Slice((*byte)(attr.pValue), attr.valueLen)
					matches = matches && bytes.Equal(object[attr.typ], want)
				}
				if matches {
					found = append(found, ckULong(i+1))
				}
			}
			return ckrOK
		},
		findObjects: func(_ ckULong, handles *ckULong, capacity ckULong, count *ckULong) ckULong {
			*count = ckULong(copy(unsafe.Slice(handles, capacity), found))
			return ckrOK
		},
		findObjectsFinal: func(ckULong) ckULong { return ckrOK },
		getAttributeValue: func(_, handle ckULong, attr *ckAttribute, _ ckULong) ckULong {
			value := objects[handle-1][attr.typ]
			if attr.pValue != nil {
				copy(unsafe.Slice((*byte)(attr.pValue), attr.valueLen), value)
			}
			attr.valueLen = ckULong(len(value))
			return ckrOK
		},
	}
}

// classValue is a CKA_CLASS value as the binding passes it: a CK_ULONG in host
// byte order.
func classValue(class uint64) []byte {
	return binary.NativeEndian.AppendUint64(nil, class)
}

func fakePrivateKey(label, id string) fakeObject {
	return fakeObject{ckaClass: classValue(ckoPrivateKey), ckaLabel: []byte(label), ckaID: []byte(id)}
}

func fakePublicKey(t *testing.T, key *ecdsa.PrivateKey, label, id string) fakeObject {
	t.Helper()
	params, err := asn1.Marshal(oidP256)
	require.NoError(t, err)
	q, err := key.PublicKey.Bytes()
	require.NoError(t, err)
	point, err := asn1.Marshal(q)
	require.NoError(t, err)
	return fakeObject{
		ckaClass:    classValue(ckoPublicKey),
		ckaLabel:    []byte(label),
		ckaID:       []byte(id),
		ckaECParams: params,
		ckaECPoint:  point,
	}
}

// The signer must end up with the public key of its own private key, or with
// an error, whatever else on the token carries the same label.
func TestKeyPairLookup(t *testing.T) {
	ownKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	foreignKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	own := func(label, id string) fakeObject { return fakePublicKey(t, ownKey, label, id) }
	foreign := func(label, id string) fakeObject { return fakePublicKey(t, foreignKey, label, id) }

	tests := []struct {
		name    string
		objects []fakeObject
		wantErr string
	}{
		{
			name:    "foreign public key under the same label",
			objects: []fakeObject{fakePrivateKey("key", "01"), foreign("key", "02"), own("key", "01")},
		},
		{
			name:    "own public key under another label",
			objects: []fakeObject{fakePrivateKey("key", "01"), foreign("key", "02"), own("other", "01")},
		},
		{
			name:    "own public key missing",
			objects: []fakeObject{fakePrivateKey("key", "01"), foreign("key", "02")},
			wantErr: `public key of private key "key": not found`,
		},
		{
			name:    "two public keys with the ID of the private key",
			objects: []fakeObject{fakePrivateKey("key", "01"), own("key", "01"), foreign("other", "01")},
			wantErr: `public key of private key "key": more than one object matches`,
		},
		{
			name:    "no ID, public key found by label",
			objects: []fakeObject{fakePrivateKey("key", ""), own("key", ""), foreign("other", "")},
		},
		{
			name:    "no ID, two public keys under the label",
			objects: []fakeObject{fakePrivateKey("key", ""), own("key", ""), foreign("key", "02")},
			wantErr: `public key of private key "key": more than one object matches`,
		},
		{
			name:    "two private keys under the label",
			objects: []fakeObject{fakePrivateKey("key", "01"), fakePrivateKey("key", "02"), own("key", "01")},
			wantErr: `private key with label "key": more than one object matches`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &session{mod: newFakeModule(tt.objects)}
			pub, err := s.setup(fakeTokenLabel, "key", []byte("1234"))
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.True(t, pub.Equal(&ownKey.PublicKey))
		})
	}
}

// A module that reports a length it cannot back must cause an error, not a
// panic in make or in a slice expression.
func TestModuleReportedLengths(t *testing.T) {
	tests := []struct {
		name string
		// first is the length reported to the length query, second the
		// length reported when the buffer is passed.
		first, second ckULong
		slotErr       string
		attributeErr  string
	}{
		{
			name:         "above the limit",
			first:        1 << 62,
			slotErr:      "module reports 4611686018427387904 slots, limit is 1024",
			attributeErr: "attribute 0x102: module reports 4611686018427387904 bytes, limit is 65536",
		},
		{
			name:         "CK_UNAVAILABLE_INFORMATION",
			first:        ckUnavailableInformation,
			slotErr:      "module reports 18446744073709551615 slots, limit is 1024",
			attributeErr: "attribute 0x102 is not available",
		},
		{
			name:         "longer on the second call",
			first:        1,
			second:       2,
			slotErr:      "module reports 2 slots after reporting 1",
			attributeErr: "attribute 0x102: module reports 2 bytes after reporting 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod := &module{
				getSlotList: func(_ uint8, slots *ckULong, count *ckULong) ckULong {
					*count = tt.first
					if slots != nil {
						*count = tt.second
					}
					return ckrOK
				},
				getAttributeValue: func(_, _ ckULong, attr *ckAttribute, _ ckULong) ckULong {
					if attr.pValue == nil {
						attr.valueLen = tt.first
					} else {
						attr.valueLen = tt.second
					}
					return ckrOK
				},
			}

			_, err := mod.findSlot(fakeTokenLabel)
			require.EqualError(t, err, tt.slotErr)
			_, err = mod.attribute(1, 1, ckaID)
			require.EqualError(t, err, tt.attributeErr)
		})
	}
}

// The module has two slots with a token of the same label in each. With
// secondRV set, C_GetTokenInfo fails with it for the second slot.
func TestFindSlot(t *testing.T) {
	const deviceError = 0x30 // CKR_DEVICE_ERROR
	tests := []struct {
		name     string
		secondRV ckULong
		label    string
		wantErr  string
	}{
		{"two tokens with the label", ckrOK, fakeTokenLabel, `2 tokens with label "fake token"`},
		{"no token with the label", ckrOK, "other", `no token with label "other"`},
		{"unreadable slot next to the token", deviceError, fakeTokenLabel, ""},
		{"unreadable slot, no token with the label", deviceError, "other", `no token with label "other": C_GetTokenInfo: CKR_DEVICE_ERROR`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod := newFakeModule(nil)
			mod.getSlotList = func(_ uint8, slots *ckULong, count *ckULong) ckULong {
				if slots != nil {
					copy(unsafe.Slice(slots, 2), []ckULong{1, 2})
				}
				*count = 2
				return ckrOK
			}
			readable := mod.getTokenInfo
			mod.getTokenInfo = func(slot ckULong, info *ckTokenInfo) ckULong {
				if slot == 2 && tt.secondRV != ckrOK {
					return tt.secondRV
				}
				return readable(slot, info)
			}

			slot, err := mod.findSlot(tt.label)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, ckULong(1), slot)
		})
	}
}

// C_Sign reports how many bytes it wrote. Anything but the full r||s must not
// be passed on as a signature.
func TestShortSignature(t *testing.T) {
	s := &session{sigLen: 64, mod: &module{
		signInit: func(ckULong, *ckMechanism, ckULong) ckULong { return ckrOK },
		sign: func(_ ckULong, _ *byte, _ ckULong, _ *byte, n *ckULong) ckULong {
			*n = 63
			return ckrOK
		},
	}}

	_, err := s.signDigest(make([]byte, 32))
	require.EqualError(t, err, "C_Sign returned 63 bytes, want 64")
}
