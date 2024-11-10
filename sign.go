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

// Helper function to create and sign a DSSE envelope without double-wrapping
func createAndSignEnvelopeWithSubject(payload interface{}, dataType string, subjects map[string]cryptoutil.DigestSet, opts ...dsse.SignOption) (dsse.Envelope, error) {
	var stmt intoto.Statement

	// Check if payload is already an intoto statement
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("failed to marshal payload: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, &stmt); err == nil && stmt.Type == "https://in-toto.io/Statement/v0.1" {
		// Append user-defined subjects to existing in-toto statement
		for name, ds := range subjects {
			s, err := intoto.DigestSetToSubject(name, ds)
			if err != nil {
				return dsse.Envelope{}, fmt.Errorf("failed to convert digest set to subject: %w", err)
			}
			stmt.Subject = append(stmt.Subject, s)
		}
	} else {
		// Handle error or create new statement if payload is not an in-toto statement
		return dsse.Envelope{}, errors.New("payload is not a valid in-toto statement")
	}

	// Marshal the modified statement and sign without re-wrapping
	stmtJson, err := json.Marshal(&stmt)
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("failed to marshal intoto statement: %w", err)
	}

	return dsse.Sign(dataType, bytes.NewReader(stmtJson), opts...)
}
