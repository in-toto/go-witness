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

package gcpiit

import "testing"

// TestBuildInstanceEndpoints_NoProjectRoutes reproduces issue #258: the
// workload-identity metadata fetch queried "project-id"/"project-number" at
// InstanceMetadataUrl+"project/..." (e.g.
// http://metadata.google.internal/computeMetadata/v1/instance/project/project-id),
// which is not a valid GCE metadata route (the real project route is
// ProjectMetadataUrl, i.e. .../v1/project/project-id, with no "/instance"
// segment) and always returned 404, logging a warning on every attestation.
// Worse, the fetched values were never used: getInstanceData overwrites
// a.ProjectID/a.ProjectNumber unconditionally from parseJWTProjectInfo a few
// lines later. The two routes should not be queried at all.
func TestBuildInstanceEndpoints_NoProjectRoutes(t *testing.T) {
	endpoints := buildInstanceEndpoints()

	for _, key := range []string{"project-id", "project-number"} {
		if url, ok := endpoints[key]; ok {
			t.Errorf("buildInstanceEndpoints must not query %q (dead code: value is always "+
				"overwritten by parseJWTProjectInfo, and route %q is invalid), but it maps to %q",
				key, key, url)
		}
	}

	wantKeys := []string{"hostname", "id", "zone", "cluster-name", "cluster-uid", "cluster-location"}
	if len(endpoints) != len(wantKeys) {
		t.Errorf("buildInstanceEndpoints returned %d routes, want %d (%v); got %v",
			len(endpoints), len(wantKeys), wantKeys, endpoints)
	}
	for _, k := range wantKeys {
		if _, ok := endpoints[k]; !ok {
			t.Errorf("buildInstanceEndpoints missing expected route %q", k)
		}
	}
}
