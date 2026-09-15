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

//go:build linux

package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/in-toto/go-witness/attestation/networktrace/types"
)

// Protocol detection and TLS utilities for transparent HTTPS proxying

// detectProtocol peeks at connection bytes to determine protocol
func detectProtocol(br *bufio.Reader) (string, error) {
	// Peek at the first 24 bytes (enough for TLS, HTTP detection)
	header, err := br.Peek(24)
	if err != nil && !errors.Is(err, bufio.ErrBufferFull) && err != io.EOF {
		return "", fmt.Errorf("peek connection: %w", err)
	}

	if len(header) < 5 {
		return "unknown", nil
	}

	// Check for TLS: ContentType (0x16=Handshake) + Version (0x03 0x00-0x03)
	if header[0] == 0x16 && header[1] == 0x03 &&
		(header[2] == 0x00 || header[2] == 0x01 || header[2] == 0x02 || header[2] == 0x03) {
		return "tls", nil
	}

	// Check for HTTP methods
	headerStr := string(header)
	methods := []string{"GET ", "POST", "PUT ", "HEAD", "DELE", "OPTI", "PATC", "TRAC", "CONN"}
	for _, method := range methods {
		if len(headerStr) >= len(method) && headerStr[:len(method)] == method {
			return "http", nil
		}
	}

	// TODO: Verify support for HTTP/2 detection if needed

	return "unknown", nil
}

// parseSNIExtension parses the SNI extension data
func parseSNIExtension(data []byte) (string, error) {
	// SNI Extension format:
	// [0-1]  Server Name List Length
	// [2]    Server Name Type (0 = host_name)
	// [3-4]  Server Name Length
	// [5...] Server Name

	if len(data) < 5 {
		return "", fmt.Errorf("SNI extension too short")
	}

	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen+2 > len(data) {
		return "", fmt.Errorf("invalid SNI list length")
	}

	pos := 2
	nameType := data[pos]
	if nameType != 0x00 { // Not host_name
		return "", fmt.Errorf("unsupported SNI name type: 0x%x", nameType)
	}

	pos++
	nameLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	if pos+nameLen > len(data) {
		return "", fmt.Errorf("invalid SNI name length")
	}

	hostname := string(data[pos : pos+nameLen])
	return hostname, nil
}

// ParsedClientHello contains parsed ClientHello information
type ParsedClientHello struct {
	SNI           string
	ClientHello   *types.ClientHelloInfo
	LegacyVersion uint16 // Legacy version field from ClientHello
}

// parseClientHelloFromBufferedReader parses ClientHello from an existing buffered reader by peeking
// This preserves all data in the buffer for subsequent reads
// Returns SNI and full ClientHelloInfo including supported versions and cipher suites
func parseClientHelloFromBufferedReader(br *bufio.Reader) (*ParsedClientHello, error) {
	// Peek at TLS record to get length
	recordHeader, err := br.Peek(5)
	if err != nil {
		return nil, fmt.Errorf("peek record header: %w", err)
	}

	if recordHeader[0] != 0x16 {
		return nil, fmt.Errorf("not a TLS handshake")
	}

	recordLength := int(binary.BigEndian.Uint16(recordHeader[3:5]))
	totalLength := 5 + recordLength

	// Peek the entire TLS record (without consuming it)
	fullRecord, err := br.Peek(totalLength)
	if err != nil {
		return nil, fmt.Errorf("peek full record: %w", err)
	}

	// Parse ClientHello from the peeked data
	handshake := fullRecord[5:] // Skip record header

	if len(handshake) < 39 || handshake[0] != 0x01 {
		return nil, fmt.Errorf("invalid ClientHello")
	}

	result := &ParsedClientHello{
		ClientHello: &types.ClientHelloInfo{},
	}

	// Extract legacy version (bytes 4-5 of handshake, after msg type and length)
	result.LegacyVersion = binary.BigEndian.Uint16(handshake[4:6])

	// Parse to find extensions and cipher suites
	pos := 38
	sessionIDLen := int(handshake[pos])
	pos += 1 + sessionIDLen

	if pos+2 > len(handshake) {
		return nil, fmt.Errorf("invalid ClientHello")
	}

	// Parse cipher suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(handshake[pos : pos+2]))
	pos += 2

	if pos+cipherSuitesLen > len(handshake) {
		return nil, fmt.Errorf("invalid cipher suites length")
	}

	// Extract cipher suites (each is 2 bytes)
	cipherSuitesData := handshake[pos : pos+cipherSuitesLen]
	for i := 0; i+1 < len(cipherSuitesData); i += 2 {
		suiteID := binary.BigEndian.Uint16(cipherSuitesData[i : i+2])
		result.ClientHello.CipherSuites = append(result.ClientHello.CipherSuites, fmt.Sprintf("0x%04x", suiteID))
		// Try to get human-readable name
		if name := tls.CipherSuiteName(suiteID); name != "" && name != fmt.Sprintf("0x%04X", suiteID) {
			result.ClientHello.CipherSuiteNames = append(result.ClientHello.CipherSuiteNames, name)
		}
	}

	pos += cipherSuitesLen

	if pos+1 > len(handshake) {
		return nil, fmt.Errorf("invalid ClientHello")
	}

	compressionMethodsLen := int(handshake[pos])
	pos += 1 + compressionMethodsLen

	if pos+2 > len(handshake) {
		// No extensions, use legacy version
		result.ClientHello.SupportedVersions = []string{tlsVersionToString(result.LegacyVersion)}
		return result, nil
	}

	extensionsLen := int(binary.BigEndian.Uint16(handshake[pos : pos+2]))
	pos += 2

	extensionsEnd := pos + extensionsLen
	if extensionsEnd > len(handshake) {
		return nil, fmt.Errorf("invalid extensions")
	}

	// Parse extensions
	var foundSupportedVersions bool
	for pos+4 <= extensionsEnd {
		extensionType := binary.BigEndian.Uint16(handshake[pos : pos+2])
		extensionLen := int(binary.BigEndian.Uint16(handshake[pos+2 : pos+4]))
		pos += 4

		if pos+extensionLen > len(handshake) {
			return nil, fmt.Errorf("invalid extension")
		}

		extensionData := handshake[pos : pos+extensionLen]

		switch extensionType {
		case 0x0000: // SNI
			sni, err := parseSNIExtension(extensionData)
			if err == nil {
				result.SNI = sni
			}
		case 0x002b: // supported_versions (43)
			versions := parseSupportedVersionsExtension(extensionData)
			if len(versions) > 0 {
				result.ClientHello.SupportedVersions = versions
				foundSupportedVersions = true
			}
		}

		pos += extensionLen
	}

	// If no supported_versions extension, use legacy version
	if !foundSupportedVersions {
		result.ClientHello.SupportedVersions = []string{tlsVersionToString(result.LegacyVersion)}
	}

	return result, nil
}

// parseSupportedVersionsExtension parses the supported_versions extension from ClientHello
func parseSupportedVersionsExtension(data []byte) []string {
	if len(data) < 1 {
		return nil
	}

	// In ClientHello, format is: length (1 byte) + list of versions (2 bytes each)
	listLen := int(data[0])
	if listLen+1 > len(data) {
		return nil
	}

	var versions []string
	for i := 1; i+1 <= listLen+1 && i+1 < len(data); i += 2 {
		version := binary.BigEndian.Uint16(data[i : i+2])
		versions = append(versions, tlsVersionToString(version))
	}

	return versions
}

// tlsVersionToString converts a TLS version number to a human-readable string
func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}
