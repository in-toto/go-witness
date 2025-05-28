// Copyright 2024 The Witness Contributors
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

//go:build !darwin && !linux

package productarchive

import "syscall"

// setFileTimes sets the platform-specific file times
func setFileTimes(metadata *FileMetadata, stat *syscall.Stat_t) {
	// On Windows and other platforms, time fields may not be available
	// or have different names. This is a no-op fallback.
}

// getBirthTime returns nil on platforms that don't support it
func getBirthTime(stat *syscall.Stat_t) *int64 {
	return nil
}

// getXattrs returns nil on platforms that don't support extended attributes
func getXattrs(path string) (map[string]string, error) {
	return nil, nil
}
