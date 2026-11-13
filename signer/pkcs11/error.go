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

package pkcs11

import "fmt"

// ckError is a CK_RV other than CKR_OK returned by a Cryptoki function.
type ckError struct {
	fn string
	rv uint
}

func (e *ckError) Error() string {
	if name, ok := rvNames[e.rv]; ok {
		return fmt.Sprintf("%s: %s", e.fn, name)
	}
	return fmt.Sprintf("%s: CKR 0x%X", e.fn, e.rv)
}

// rvNames names the return values a user is likely to meet. Any other value
// is printed as a number.
var rvNames = map[uint]string{
	0x002: "CKR_HOST_MEMORY",
	0x003: "CKR_SLOT_ID_INVALID",
	0x005: "CKR_GENERAL_ERROR",
	0x006: "CKR_FUNCTION_FAILED",
	0x007: "CKR_ARGUMENTS_BAD",
	0x009: "CKR_NEED_TO_CREATE_THREADS",
	0x00A: "CKR_CANT_LOCK",
	0x011: "CKR_ATTRIBUTE_SENSITIVE",
	0x012: "CKR_ATTRIBUTE_TYPE_INVALID",
	0x021: "CKR_DATA_LEN_RANGE",
	0x030: "CKR_DEVICE_ERROR",
	0x032: "CKR_DEVICE_REMOVED",
	0x054: "CKR_FUNCTION_NOT_SUPPORTED",
	0x060: "CKR_KEY_HANDLE_INVALID",
	0x063: "CKR_KEY_TYPE_INCONSISTENT",
	0x068: "CKR_KEY_FUNCTION_NOT_PERMITTED",
	0x070: "CKR_MECHANISM_INVALID",
	0x082: "CKR_OBJECT_HANDLE_INVALID",
	0x090: "CKR_OPERATION_ACTIVE",
	0x091: "CKR_OPERATION_NOT_INITIALIZED",
	0x0A0: "CKR_PIN_INCORRECT",
	0x0A4: "CKR_PIN_LOCKED",
	0x0B0: "CKR_SESSION_CLOSED",
	0x0B1: "CKR_SESSION_COUNT",
	0x0B3: "CKR_SESSION_HANDLE_INVALID",
	0x0B4: "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
	0x0E0: "CKR_TOKEN_NOT_PRESENT",
	0x0E1: "CKR_TOKEN_NOT_RECOGNIZED",
	0x101: "CKR_USER_NOT_LOGGED_IN",
	0x102: "CKR_USER_PIN_NOT_INITIALIZED",
	0x103: "CKR_USER_TYPE_INVALID",
	0x150: "CKR_BUFFER_TOO_SMALL",
	0x190: "CKR_CRYPTOKI_NOT_INITIALIZED",
}
