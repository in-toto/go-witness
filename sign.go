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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/intoto"
)

// Sign parses the input, conditionally adds a user-defined subject for in-toto attestations, and then signs the DSSE envelope.
func Sign(r io.Reader, dataType string, w io.Writer, opts ...dsse.SignOption) error {
	// Create an instance of signOptions with defaults and apply provided SignOptions
	so := &dsse.SignOptions{}

	for _, opt := range opts {
		opt(so)
	}

	// Check if user-defined subject is provided
	hasUserDefinedSubject := len(so.UserDefinedSubject) > 0

	// Parse the input payload
	var payload interface{}
	if err := json.NewDecoder(r).Decode(&payload); err != nil {
		return fmt.Errorf("failed to decode input: %w", err)
	}

	// Check if the payload is an in-toto statement
	if dataType == intoto.PayloadType {
		// Create the envelope with user-defined subjects for in-toto statements
		envelope, err := createAndSignEnvelopeWithSubject(payload, dataType, so.UserDefinedSubject, opts...)
		if err != nil {
			return fmt.Errorf("failed to create and sign envelope: %w", err)
		}

		// Encode the signed envelope to output writer `w`
		encoder := json.NewEncoder(w)
		return encoder.Encode(&envelope)
	} else if hasUserDefinedSubject {
		// If the payload is not in-toto and a subject was provided, throw an error
		return errors.New("user-defined subject is only allowed for in-toto statements")
	}

	// For non-in-toto statements without user-defined subject, create the envelope as usual
	envelope, err := dsse.Sign(dataType, r, opts...)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(w)
	return encoder.Encode(&envelope)
}

// Helper function to create and sign a DSSE envelope with a user-defined subject for in-toto attestations
func createAndSignEnvelopeWithSubject(payload interface{}, dataType string, userDefinedSubject map[string]cryptoutil.DigestSet, opts ...dsse.SignOption) (dsse.Envelope, error) {
	// Marshal the payload
	data, err := json.Marshal(&payload)
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create an intoto statement with the user-defined subject
	stmt, err := intoto.NewStatement(dataType, data, userDefinedSubject)
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("failed to create intoto statement: %w", err)
	}

	stmtJson, err := json.Marshal(&stmt)
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("failed to marshal intoto statement: %w", err)
	}

	// Sign the envelope with the statement and options
	return dsse.Sign(intoto.PayloadType, bytes.NewReader(stmtJson), opts...)
}
