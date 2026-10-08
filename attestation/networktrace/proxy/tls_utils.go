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
	"fmt"

	"github.com/in-toto/go-witness/attestation/networktrace/types"
)

// Protocol detection and TLS utilities for transparent HTTPS proxying

// h2cPreface is the HTTP/2 cleartext connection preface (RFC 9113 section 3.4).
const h2cPreface = "PRI * HTTP/2.0"

// httpMethodPrefixes is the fixed table of HTTP/1.x request-line method
// prefixes this proxy MITMs. A table miss means passthrough: matching generic
// token shapes would misroute non-HTTP protocols (e.g. Redis "PING") into
// goproxy, which would answer them with an error response and kill the
// connection.
var httpMethodPrefixes = []string{
	"GET ", "HEAD ", "POST ", "PUT ", "DELETE ",
	"CONNECT ", "OPTIONS ", "TRACE ", "PATCH ",
	"PROPFIND ", "REPORT ",
}

// protoNode is a node in the prefix tree (trie) of request prefixes this
// proxy recognizes. It is built once at init from httpMethodPrefixes and
// h2cPreface, so detection allocates nothing per connection and each peeked
// byte costs one lookup over the node's few edges (at most 8 at the root)
// instead of a scan of the whole table. trie does prefix matching efficiently.
// O(n) where n is the length of the word to be searched.
type protoNode struct {
	edges  []protoEdge
	accept string // "http" or "h2c" when a complete prefix ends at this node
}

type protoEdge struct {
	b    byte
	node *protoNode
}

func (n *protoNode) child(b byte) *protoNode {
	for _, e := range n.edges {
		if e.b == b {
			return e.node
		}
	}
	return nil
}

func (n *protoNode) insert(prefix, accept string) {
	cur := n
	for i := range len(prefix) {
		next := cur.child(prefix[i])
		if next == nil {
			next = &protoNode{}
			cur.edges = append(cur.edges, protoEdge{b: prefix[i], node: next})
		}
		cur = next
	}
	cur.accept = accept
}

var protoTrie = func() *protoNode {
	root := &protoNode{}
	for _, m := range httpMethodPrefixes {
		root.insert(m, "http")
	}
	root.insert(h2cPreface, "h2c")
	return root
}()

// detectProtocol classifies a connection's first bytes as "tls", "http", or
// "h2c" (HTTP/2 cleartext preface). It is best-effort by design: unknown
// protocols, idle clients, first bytes arriving after the caller's read
// deadline, and truncated first flights all return "", the caller must then
// fall back to transparent TCP passthrough, never hold the connection open
// waiting for more evidence.
func detectProtocol(br *bufio.Reader) string {
	first, err := br.Peek(1)
	if err != nil {
		return ""
	}

	if first[0] == 0x16 { // TLS record: ContentType=Handshake
		v, err := br.Peek(2)
		if err != nil || v[1] != 0x03 {
			return "" // not a TLS major version: diverged at byte 2
		}
		h, err := br.Peek(5)
		if err == nil && h[2] <= 0x04 {
			return "tls" // 5-byte record header confirmed (legacy version 0x0300-0x0304)
		}
		return "" // truncated or unknown legacy version
	}

	// Walk the prefix tree one peeked byte at a time. A byte with no root
	// edge (e.g. the Gradle "ac" magic) exits immediately, any later
	// divergence ends the walk at that byte. matched keeps the longest
	// complete prefix seen so far.
	node := protoTrie.child(first[0])
	matched := ""
	for i := 2; node != nil; i++ {
		if node.accept != "" {
			matched = node.accept
		}
		if len(node.edges) == 0 {
			break // leaf: nothing longer can match
		}
		h, err := br.Peek(i)
		if err != nil {
			break // truncated or idle: keep what already completed
		}
		node = node.child(h[i-1])
	}
	return matched
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
