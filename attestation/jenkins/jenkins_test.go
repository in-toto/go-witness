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

package jenkins

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSubjects(t *testing.T) {
	attestor := &Attestor{}

	subjects := attestor.Subjects()
	assert.NotNil(t, subjects)
	assert.Equal(t, 2, len(subjects))

	expectedSubjects := []string{"pipelineurl:" + attestor.PipelineUrl, "jenkinsurl:" + attestor.JenkinsUrl}
	for _, expectedSubject := range expectedSubjects {
		_, ok := subjects[expectedSubject]
		assert.True(t, ok, "Expected subject not found: %s", expectedSubject)
	}
	m := attestor.BackRefs()
	assert.NotNil(t, m)
	assert.Equal(t, 1, len(m))
}
