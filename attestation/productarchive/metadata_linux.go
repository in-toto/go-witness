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

//go:build linux

package productarchive

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// setFileTimes sets the platform-specific file times
func setFileTimes(metadata *FileMetadata, stat *syscall.Stat_t) {
	metadata.AccessTime = stat.Atim.Sec
	metadata.ChangeTime = stat.Ctim.Sec
}

// getBirthTime returns nil on Linux as birth time is not consistently available
func getBirthTime(stat *syscall.Stat_t) *int64 {
	// Birth time (btime) is available in statx on newer Linux kernels,
	// but not in the standard stat structure
	return nil
}

// getXattrs retrieves extended attributes for a file on Linux
func getXattrs(path string) (map[string]string, error) {
	// Get list of attribute names
	size, err := unix.Listxattr(path, nil)
	if err != nil || size == 0 {
		return nil, err
	}

	buf := make([]byte, size)
	_, err = unix.Listxattr(path, buf)
	if err != nil {
		return nil, err
	}

	xattrs := make(map[string]string)
	for len(buf) > 0 {
		// Find null terminator
		i := 0
		for i < len(buf) && buf[i] != 0 {
			i++
		}
		if i == 0 {
			break
		}

		name := string(buf[:i])

		// Get attribute value
		valueSize, err := unix.Getxattr(path, name, nil)
		if err != nil || valueSize == 0 {
			buf = buf[i+1:]
			continue
		}

		value := make([]byte, valueSize)
		_, err = unix.Getxattr(path, name, value)
		if err == nil {
			xattrs[name] = string(value)
		}

		buf = buf[i+1:]
	}

	return xattrs, nil
}
