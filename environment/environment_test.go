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

package environment

import (
	"reflect"
	"testing"
)

func Test_splitVariable(t *testing.T) {
	type args struct {
		v string
	}
	tests := []struct {
		name    string
		args    args
		wantKey string
		wantVal string
	}{
		{
			name: "KEY=VALUE",
			args: args{
				v: "KEY=VALUE",
			},
			wantKey: "KEY",
			wantVal: "VALUE",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotVal := splitVariable(tt.args.v)
			if gotKey != tt.wantKey {
				t.Errorf("splitVariable() gotKey = %v, want %v", gotKey, tt.wantKey)
			}
			if gotVal != tt.wantVal {
				t.Errorf("splitVariable() gotVal = %v, want %v", gotVal, tt.wantVal)
			}
		})
	}
}

func TestCapture_Capture(t *testing.T) {
	type fields struct {
		sensitiveVarsList           map[string]struct{}
		addSensitiveVarsList        map[string]struct{}
		excludeSensitiveVarsList    map[string]struct{}
		filterVarsEnabled           bool
		disableSensitiveVarsDefault bool
	}
	type args struct {
		env []string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   map[string]string
	}{
		{
			name: "Obfuscate *_TOKEN",
			fields: fields{
				sensitiveVarsList:           DefaultSensitiveEnvList(),
				addSensitiveVarsList:        map[string]struct{}{},
				excludeSensitiveVarsList:    map[string]struct{}{},
				filterVarsEnabled:           false,
				disableSensitiveVarsDefault: false,
			},
			args: args{
				env: []string{
					"TEST_TOKEN=password",
					"TEST_TEXT=value",
				},
			},
			want: map[string]string{
				"TEST_TOKEN": "******",
				"TEST_TEXT":  "value",
			},
		},
		{
			name: "Filter *_TOKEN",
			fields: fields{
				sensitiveVarsList:           DefaultSensitiveEnvList(),
				addSensitiveVarsList:        map[string]struct{}{},
				excludeSensitiveVarsList:    map[string]struct{}{},
				filterVarsEnabled:           true,
				disableSensitiveVarsDefault: false,
			},
			args: args{
				env: []string{
					"TEST_TOKEN=password",
					"TEST_TEXT=value",
				},
			},
			want: map[string]string{
				"TEST_TEXT": "value",
			},
		},
		{
			name: "Disable sensitive vars",
			fields: fields{
				sensitiveVarsList:           DefaultSensitiveEnvList(),
				addSensitiveVarsList:        map[string]struct{}{},
				excludeSensitiveVarsList:    map[string]struct{}{},
				filterVarsEnabled:           true,
				disableSensitiveVarsDefault: true,
			},
			args: args{
				env: []string{
					"TEST_TOKEN=password",
					"TEST_TEXT=value",
				},
			},
			want: map[string]string{
				"TEST_TOKEN": "password",
				"TEST_TEXT":  "value",
			},
		},
		{
			name: "Obfuscate custom sensitive vars",
			fields: fields{
				sensitiveVarsList: DefaultSensitiveEnvList(),
				addSensitiveVarsList: map[string]struct{}{
					"*_BLA": {},
				},
				excludeSensitiveVarsList:    map[string]struct{}{},
				filterVarsEnabled:           false,
				disableSensitiveVarsDefault: true,
			},
			args: args{
				env: []string{
					"TEST_BLA=password",
					"TEST_TEXT=value",
				},
			},
			want: map[string]string{
				"TEST_BLA":  "******",
				"TEST_TEXT": "value",
			},
		},
		{
			name: "Filter custom sensitive vars",
			fields: fields{
				sensitiveVarsList: DefaultSensitiveEnvList(),
				addSensitiveVarsList: map[string]struct{}{
					"*_BLA": {},
				},
				excludeSensitiveVarsList:    map[string]struct{}{},
				filterVarsEnabled:           true,
				disableSensitiveVarsDefault: true,
			},
			args: args{
				env: []string{
					"TEST_BLA=password",
					"TEST_TEXT=value",
				},
			},
			want: map[string]string{
				"TEST_TEXT": "value",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Capture{
				sensitiveVarsList:           tt.fields.sensitiveVarsList,
				addSensitiveVarsList:        tt.fields.addSensitiveVarsList,
				excludeSensitiveVarsList:    tt.fields.excludeSensitiveVarsList,
				filterVarsEnabled:           tt.fields.filterVarsEnabled,
				disableSensitiveVarsDefault: tt.fields.disableSensitiveVarsDefault,
			}
			if got := c.Capture(tt.args.env); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Capture.Capture() = %v, want %v", got, tt.want)
			}
		})
	}
}

func _TestWith() CaptureOption {
	return func(c *Capture) {
		c.filterVarsEnabled = true
	}
}

func TestNew(t *testing.T) {
	type args struct {
		opts []CaptureOption
	}
	tests := []struct {
		name string
		args args
		want *Capture
	}{
		{
			name: "With",
			args: args{
				opts: []CaptureOption{_TestWith()},
			},
			want: &Capture{
				filterVarsEnabled: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.opts...); got.filterVarsEnabled != tt.want.filterVarsEnabled {
				t.Errorf("New() = %v, want %v", got.filterVarsEnabled, tt.want.filterVarsEnabled)
			}
		})
	}
}
