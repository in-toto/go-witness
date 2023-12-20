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
	"fmt"
	"io"

	"github.com/in-toto/go-witness/cryptoutil"
	idsse "github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/intoto"
	"github.com/in-toto/go-witness/signature/envelope"
	dsse "github.com/in-toto/go-witness/signature/envelope/dsse"
)

type signOptions struct {
	signer       cryptoutil.Signer
	envelopeType string
}

type SignOption func(ro *signOptions)

func SignWithEnvelopeType(envelopeType string) SignOption {
	return func(so *signOptions) {
		so.envelopeType = envelopeType
	}
}

func Sign(s cryptoutil.Signer, r io.Reader, dataType string, w io.Writer, envelopeType string) error {
	stmtJson, err := io.ReadAll(r)
	var env envelope.Envelope
	switch envelopeType {
	case "dsse":
		env = &dsse.Envelope{
			Envelope: &idsse.Envelope{
				PayloadType: intoto.PayloadType,
				Payload:     string([]byte(stmtJson)),
			},
		}
	default:
		return fmt.Errorf("envelope type %s not recognized", envelopeType)
	}

	err = env.Sign(&s)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(w)
	return encoder.Encode(&env)
}
