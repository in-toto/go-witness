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

package githubwebhook

type Option func(*Attestor)

func WithBody(body []byte) Option {
	return func(a *Attestor) {
		a.body = body
	}
}

func WithSecret(secret []byte) Option {
	return func(a *Attestor) {
		a.secret = secret
	}
}

func WithRecievedSignature(recievedSig string) Option {
	return func(a *Attestor) {
		a.receivedSig = recievedSig
	}
}

func WithEvent(event string) Option {
	return func(a *Attestor) {
		a.Event = event
	}
}
