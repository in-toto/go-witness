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
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
)

// CK_ULONG is unsigned long, which is pointer-sized on LP64 Unix. The structs
// below follow the natural C layout; the 1-byte packing in the PKCS#11 headers
// applies on Windows only. Members the signer never touches are blank fields
// that only hold the layout.
type ckULong = uintptr

// pValue is an unsafe.Pointer so that the garbage collector sees the buffer
// through the template.
type ckAttribute struct {
	typ      ckULong
	pValue   unsafe.Pointer
	valueLen ckULong
}

type ckMechanism struct {
	mechanism ckULong
	_         unsafe.Pointer // pParameter
	_         ckULong        // ulParameterLen
}

type ckCInitializeArgs struct {
	_     [4]uintptr // CreateMutex, DestroyMutex, LockMutex, UnlockMutex
	flags ckULong
	_     unsafe.Pointer // pReserved
}

type ckTokenInfo struct {
	label [32]byte
	_     [64]byte    // manufacturerID, model, serialNumber
	_     [11]ckULong // flags, session counts, PIN lengths, memory sizes
	_     [20]byte    // hardwareVersion, firmwareVersion, utcTime
}

// CK_FUNCTION_LIST of Cryptoki 2.x: CK_VERSION, 6 bytes of padding, then 68
// function pointers in the order of pkcs11f.h.
type ckFunctionList struct {
	_  [2]byte // version
	fn [68]uintptr
}

// Sizes and offsets measured with gcc on linux/amd64 and linux/arm64. A
// mismatch is a build error.
var (
	_ [24]struct{}  = [unsafe.Sizeof(ckAttribute{})]struct{}{}
	_ [8]struct{}   = [unsafe.Offsetof(ckAttribute{}.pValue)]struct{}{}
	_ [16]struct{}  = [unsafe.Offsetof(ckAttribute{}.valueLen)]struct{}{}
	_ [24]struct{}  = [unsafe.Sizeof(ckMechanism{})]struct{}{}
	_ [0]struct{}   = [unsafe.Offsetof(ckMechanism{}.mechanism)]struct{}{}
	_ [48]struct{}  = [unsafe.Sizeof(ckCInitializeArgs{})]struct{}{}
	_ [32]struct{}  = [unsafe.Offsetof(ckCInitializeArgs{}.flags)]struct{}{}
	_ [208]struct{} = [unsafe.Sizeof(ckTokenInfo{})]struct{}{}
	_ [0]struct{}   = [unsafe.Offsetof(ckTokenInfo{}.label)]struct{}{}
	_ [552]struct{} = [unsafe.Sizeof(ckFunctionList{})]struct{}{}
	_ [8]struct{}   = [unsafe.Offsetof(ckFunctionList{}.fn)]struct{}{}
)

const (
	ckfSerialSession = 0x4
	ckfOSLockingOK   = 0x2
	ckuUser          = 1
	ckoPublicKey     = 2
	ckoPrivateKey    = 3
	ckaClass         = 0x0
	ckaLabel         = 0x3
	ckaID            = 0x102
	ckaECParams      = 0x180
	ckaECPoint       = 0x181
	ckmECDSA         = 0x1041

	ckrOK                         = 0x0
	ckrUserAlreadyLoggedIn        = 0x100
	ckrCryptokiAlreadyInitialized = 0x191

	ckUnavailableInformation = ^ckULong(0)
)

// Lengths that the module reports are checked against these limits before
// they are used to allocate, so that a broken module causes an error and not
// a panic. The values are arbitrary ceilings: SoftHSM with one token reports
// 2 slots, and a P-384 CKA_EC_POINT has 99 bytes.
const (
	maxSlots        = 1024
	maxAttributeLen = 1 << 16
)

type module struct {
	initialize        func(args *ckCInitializeArgs) ckULong
	getSlotList       func(tokenPresent uint8, slots *ckULong, count *ckULong) ckULong
	getTokenInfo      func(slot ckULong, info *ckTokenInfo) ckULong
	openSession       func(slot, flags ckULong, app unsafe.Pointer, notify uintptr, session *ckULong) ckULong
	closeSession      func(session ckULong) ckULong
	login             func(session, userType ckULong, pin *byte, pinLen ckULong) ckULong
	getAttributeValue func(session, object ckULong, tmpl *ckAttribute, count ckULong) ckULong
	findObjectsInit   func(session ckULong, tmpl *ckAttribute, count ckULong) ckULong
	findObjects       func(session ckULong, objects *ckULong, max ckULong, count *ckULong) ckULong
	findObjectsFinal  func(session ckULong) ckULong
	signInit          func(session ckULong, mech *ckMechanism, key ckULong) ckULong
	sign              func(session ckULong, data *byte, dataLen ckULong, sig *byte, sigLen *ckULong) ckULong
}

// load maps the module and binds the functions the signer uses. Only
// C_GetFunctionList is looked up by name; everything else is taken from the
// table it returns, because a module's exported C_* symbols need not be the
// functions in its table. The library is never unloaded.
func load(path string) (*module, error) {
	lib, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, fmt.Errorf("load module: %w", err)
	}

	sym, err := purego.Dlsym(lib, "C_GetFunctionList")
	if err != nil {
		return nil, fmt.Errorf("%s is not a PKCS#11 module: %w", path, err)
	}

	var getFunctionList func(**ckFunctionList) ckULong
	purego.RegisterFunc(&getFunctionList, sym)
	// The module stores the address of its own table in list.
	var list *ckFunctionList
	if rv := getFunctionList(&list); rv != ckrOK {
		return nil, &ckError{"C_GetFunctionList", uint(rv)}
	}

	if list == nil {
		return nil, fmt.Errorf("%s returned no function list", path)
	}

	m := &module{}
	// index is the position of the function in pkcs11f.h, counted from 0. Its
	// pointer is at offset 8 + 8*index of CK_FUNCTION_LIST.
	for _, f := range []struct {
		index int
		name  string
		fptr  any
	}{
		{0, "C_Initialize", &m.initialize},
		{4, "C_GetSlotList", &m.getSlotList},
		{6, "C_GetTokenInfo", &m.getTokenInfo},
		{12, "C_OpenSession", &m.openSession},
		{13, "C_CloseSession", &m.closeSession},
		{18, "C_Login", &m.login},
		{24, "C_GetAttributeValue", &m.getAttributeValue},
		{26, "C_FindObjectsInit", &m.findObjectsInit},
		{27, "C_FindObjects", &m.findObjects},
		{28, "C_FindObjectsFinal", &m.findObjectsFinal},
		{42, "C_SignInit", &m.signInit},
		{43, "C_Sign", &m.sign},
	} {
		// RegisterFunc panics on a nil function pointer.
		if list.fn[f.index] == 0 {
			return nil, fmt.Errorf("%s does not implement %s", path, f.name)
		}

		purego.RegisterFunc(f.fptr, list.fn[f.index])
	}

	return m, nil
}

func (m *module) findSlot(tokenLabel string) (ckULong, error) {
	var n ckULong
	if rv := m.getSlotList(1, nil, &n); rv != ckrOK {
		return 0, &ckError{"C_GetSlotList", uint(rv)}
	}

	if n > maxSlots {
		return 0, fmt.Errorf("module reports %d slots, limit is %d", n, maxSlots)
	}

	slots := make([]ckULong, n)
	if n > 0 {
		if rv := m.getSlotList(1, unsafe.SliceData(slots), &n); rv != ckrOK {
			return 0, &ckError{"C_GetSlotList", uint(rv)}
		}
	}

	// The second call reports the count again; it must fit what was allocated.
	if n > ckULong(len(slots)) {
		return 0, fmt.Errorf("module reports %d slots after reporting %d", n, len(slots))
	}

	var found []ckULong
	var infoErr error
	for _, slot := range slots[:n] {
		var info ckTokenInfo
		// A slot whose token cannot be read must not hide the other tokens.
		// Its error is reported only when the label is not found.
		if rv := m.getTokenInfo(slot, &info); rv != ckrOK {
			infoErr = &ckError{"C_GetTokenInfo", uint(rv)}
			continue
		}

		// The label is padded with spaces to 32 bytes and has no terminator.
		if string(bytes.TrimRight(info.label[:], " ")) == tokenLabel {
			found = append(found, slot)
		}
	}

	switch len(found) {
	case 0:
		if infoErr != nil {
			return 0, fmt.Errorf("no token with label %q: %w", tokenLabel, infoErr)
		}

		return 0, fmt.Errorf("no token with label %q", tokenLabel)
	case 1:
		return found[0], nil
	}

	return 0, fmt.Errorf("%d tokens with label %q", len(found), tokenLabel)
}

// findObject returns the one object of the class whose attribute attrType
// equals value.
func (m *module) findObject(session, class, attrType ckULong, value []byte) (ckULong, error) {
	tmpl := []ckAttribute{
		{ckaClass, unsafe.Pointer(&class), unsafe.Sizeof(class)},
		{attrType, unsafe.Pointer(unsafe.SliceData(value)), ckULong(len(value))},
	}
	// The template is Go memory that holds Go pointers. purego keeps the
	// template itself alive for the call but does not look inside it, so what
	// it points to is pinned, as the cgo rules require.
	var pin runtime.Pinner
	defer pin.Unpin()
	pin.Pin(&class)
	pin.Pin(unsafe.SliceData(value))

	if rv := m.findObjectsInit(session, unsafe.SliceData(tmpl), ckULong(len(tmpl))); rv != ckrOK {
		return 0, &ckError{"C_FindObjectsInit", uint(rv)}
	}

	// Two handles are enough to tell one match from several.
	// C_FindObjectsFinal only ends the search, also when C_FindObjects failed,
	// so its result is not checked.
	var objects [2]ckULong
	var n ckULong
	rv := m.findObjects(session, &objects[0], ckULong(len(objects)), &n)
	m.findObjectsFinal(session)
	if rv != ckrOK {
		return 0, &ckError{"C_FindObjects", uint(rv)}
	}

	switch n {
	case 0:
		return 0, errors.New("not found")
	case 1:
		return objects[0], nil
	}

	return 0, errors.New("more than one object matches")
}

func (m *module) attribute(session, object, typ ckULong) ([]byte, error) {
	attr := &ckAttribute{typ: typ}
	// With pValue NULL the module reports the length. On a missing attribute
	// it reports CK_UNAVAILABLE_INFORMATION instead.
	if rv := m.getAttributeValue(session, object, attr, 1); rv != ckrOK {
		return nil, &ckError{"C_GetAttributeValue", uint(rv)}
	}

	if attr.valueLen == ckUnavailableInformation {
		return nil, fmt.Errorf("attribute 0x%X is not available", typ)
	}

	if attr.valueLen > maxAttributeLen {
		return nil, fmt.Errorf("attribute 0x%X: module reports %d bytes, limit is %d", typ, attr.valueLen, maxAttributeLen)
	}

	buf := make([]byte, attr.valueLen)
	var pin runtime.Pinner
	defer pin.Unpin()
	pin.Pin(unsafe.SliceData(buf))
	attr.pValue = unsafe.Pointer(unsafe.SliceData(buf))
	if rv := m.getAttributeValue(session, object, attr, 1); rv != ckrOK {
		return nil, &ckError{"C_GetAttributeValue", uint(rv)}
	}

	if attr.valueLen > ckULong(len(buf)) {
		return nil, fmt.Errorf("attribute 0x%X: module reports %d bytes after reporting %d", typ, attr.valueLen, len(buf))
	}

	return buf[:attr.valueLen], nil
}
