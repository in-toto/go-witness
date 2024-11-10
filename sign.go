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
	"github.com/in-toto/go-witness/log"
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
	var rawPayload map[string]interface{}
	if err := json.NewDecoder(r).Decode(&rawPayload); err != nil {
		return fmt.Errorf("failed to decode input payload: %w", err)
	}

	// Check if the payload is an in-toto statement
	if rawPayload["_type"] == "https://in-toto.io/Statement/v0.1" {
		log.Info("payload is in-toto")
		dataType := intoto.PayloadType

		// Convert rawPayload to a Statement
		stmt := intoto.Statement{}
		payloadBytes, err := json.Marshal(rawPayload)
		if err != nil {
			return fmt.Errorf("failed to marshal payload to bytes: %w", err)
		}
		if err := json.Unmarshal(payloadBytes, &stmt); err != nil {
			return fmt.Errorf("failed to unmarshal in-toto statement: %w", err)
		}

		for name, ds := range so.UserDefinedSubject {
			s, err := intoto.DigestSetToSubject(name, ds)
			if err != nil {
				log.Errorf("failed to convert digest set to subject: %v", err)
			}

			stmt.Subject = append(stmt.Subject, s)

		}

		// Marshal the modified statement
		finalPayload := stmt

		// Create and sign envelope with subjects
		envelope, err := createAndSignEnvelopeWithSubject(finalPayload, dataType, so.UserDefinedSubject, opts...)
		if err != nil {
			return fmt.Errorf("failed to create and sign envelope: %w", err)
		}

		// Encode the signed envelope to output writer w
		encoder := json.NewEncoder(w)
		return encoder.Encode(&envelope)
	}

	// Handle non-in-toto statements
	if hasUserDefinedSubject {
		return errors.New("user-defined subject is only allowed for in-toto statements")
	}

	envelope, err := dsse.Sign(dataType, r, opts...)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(w)
	return encoder.Encode(&envelope)
}

// Helper function to create and sign a DSSE envelope with a user-defined subject for in-toto attestations
func createAndSignEnvelopeWithSubject(payload interface{}, dataType string, subjects map[string]cryptoutil.DigestSet, opts ...dsse.SignOption) (dsse.Envelope, error) {
	// Marshal the payload
	data, err := json.Marshal(&payload)
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create an intoto statement with the user-defined subject
	stmt, err := intoto.NewStatement(dataType, data, subjects)
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
