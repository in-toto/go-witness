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

package commandrun

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Custom types for better type safety

// PID represents a process ID
type PID int

// MarshalJSON implements json.Marshaler
func (p PID) MarshalJSON() ([]byte, error) {
	return json.Marshal(int(p))
}

// UnmarshalJSON implements json.Unmarshaler
func (p *PID) UnmarshalJSON(data []byte) error {
	var i int
	if err := json.Unmarshal(data, &i); err != nil {
		return err
	}
	*p = PID(i)
	return nil
}

// FileDescriptor represents a file descriptor
type FileDescriptor int

// Define standard file descriptors
const (
	Stdin  FileDescriptor = 0
	Stdout FileDescriptor = 1
	Stderr FileDescriptor = 2
)



// TracerError provides structured error information
type TracerError struct {
	Op      string // Operation that failed
	PID     PID    // Process ID involved
	Syscall string // System call if applicable
	Err     error  // Underlying error
}

func (e *TracerError) Error() string {
	if e.Syscall != "" {
		return fmt.Sprintf("%s: pid=%d syscall=%s: %v", e.Op, e.PID, e.Syscall, e.Err)
	}
	return fmt.Sprintf("%s: pid=%d: %v", e.Op, e.PID, e.Err)
}

func (e *TracerError) Unwrap() error {
	return e.Err
}



// Helper functions

// IsSpecialPath checks if a path should be ignored
func IsSpecialPath(path string) bool {
	return strings.HasPrefix(path, "/proc/") ||
		strings.HasPrefix(path, "/dev/") ||
		strings.HasPrefix(path, "/sys/")
}

