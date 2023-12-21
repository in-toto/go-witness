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

package witness

import (
	"encoding/json"
	"io"

	"github.com/in-toto/go-witness/cryptoutil"
	idsse "github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/signature/envelope"
)

type signOptions struct {
	envelopeType string
	timestampers []idsse.Timestamper
}

type SignOption func(ro *signOptions)

func SignWithEnvelopeType(envelopeType string) SignOption {
	return func(so *signOptions) {
		so.envelopeType = envelopeType
	}
}

func SignWithTimestampers(timestampers ...idsse.Timestamper) SignOption {
	return func(so *signOptions) {
		so.timestampers = timestampers
	}
}

func Sign(s cryptoutil.Signer, r io.Reader, payloadType string, w io.Writer, opts ...SignOption) error {
	so := signOptions{}

	for _, opt := range opts {
		opt(&so)
	}

	stmtJson, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	env, err := initEnvelope(so.envelopeType, payloadType, &stmtJson)

	err = env.Sign(&s, envelope.WithTimestampers(so.timestampers))
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(w)
	return encoder.Encode(&env)
}
