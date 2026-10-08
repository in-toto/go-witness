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
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/in-toto/go-witness/attestation/networktrace/bpf"
)

func detect(t *testing.T, data []byte) string {
	t.Helper()
	return detectProtocol(bufio.NewReader(bytes.NewReader(data)))
}

func pipePair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err = ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

// promptBound is the ceiling for "the sniff exited without waiting out a
// window". It is derived from confirmWindow rather than a small fixed number:
// a regression that waits out the 2s window overshoots it, while scheduler or
// GC pauses on a loaded CI box (hundreds of ms) do not. Asserting tighter
// would test scheduler speed, not behavior.
const promptBound = confirmWindow - 500*time.Millisecond

func TestDetectProtocolTLS(t *testing.T) {
	for v := range byte(5) {
		if got := detect(t, []byte{0x16, 0x03, v, 0x00, 0x10, 0x01}); got != "tls" {
			t.Fatalf("legacy version 0x030%d: got %q, want tls", v, got)
		}
	}
	if got := detect(t, []byte{0x16, 0x02, 0x01, 0x00, 0x10}); got != "" {
		t.Fatalf("wrong major version: got %q, want empty", got)
	}
	if got := detect(t, []byte{0x16, 0x03, 0x05, 0x00, 0x10}); got != "" {
		t.Fatalf("unknown legacy version: got %q, want empty", got)
	}
}

func TestDetectProtocolHTTP(t *testing.T) {
	for _, m := range httpMethodPrefixes {
		if got := detect(t, []byte(m+"/x HTTP/1.1\r\nHost: h\r\n\r\n")); got != "http" {
			t.Fatalf("%q: got %q, want http", m, got)
		}
	}
}

func TestDetectProtocolUnknown(t *testing.T) {
	for name, data := range map[string][]byte{
		"gradle magic":  {'a', 'c', 0x00, 0x01, 0x00, 0x02},
		"smtp banner":   []byte("220 ready\r\n"),
		"ssh banner":    []byte("SSH-2.0-Go\r\n"),
		"binary":        {0x90, 0x01, 0x02, 0x03},
		"truncated get": []byte("GET"), // EOF before the method prefix completes
		"empty":         {},
		"near-miss GET": []byte("GETX /\r\n"),
		"POST no space": []byte("POST\r\n"),
		"near-miss h2c": []byte("PRI * HTTP/2.1\r\n\r\nSM\r\n\r\n"),
	} {
		if got := detect(t, data); got != "" {
			t.Fatalf("%s: got %q, want empty", name, got)
		}
	}
	if got := detect(t, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); got != "h2c" {
		t.Fatalf("h2c preface: got %q, want h2c", got)
	}
}

// TestTryRouteGradleHandshakePassthrough is the regression test for the build
// hang: a short first flight followed by a wait for the peer's reply. The old
// code stalled forever in detectProtocol's unbounded Peek(24), both on
// arbitrary ports and on 8080 via the old well-known-port fast path, so the
// original destination was never dialed and Gradle's daemon timed out after
// 120s. Detection must exit at the first diverging byte ('a' is not a
// method-start byte) and passthrough must preserve the peeked bytes.
// debugging this test using dlv, etc. will fail as this is a time dependent test.
func TestTryRouteGradleHandshakePassthrough(t *testing.T) {
	for _, port := range []uint16{46413, 8080} {
		t.Run(fmt.Sprintf("orig_port_%d", port), func(t *testing.T) {
			client, accepted := pipePair(t)
			defer client.Close()
			defer accepted.Close()
			magic := []byte{'a', 'c', 0x00, 0x01, 0x00, 0x02}
			if _, err := client.Write(magic); err != nil {
				t.Fatal(err)
			}
			// The client now parks waiting for a reply, like the Gradle daemon.

			p := &TCPProxy{} // passthrough must not touch the HTTP proxy
			meta := &bpf.ConnectionMetadata{OrigIP: net.ParseIP("127.0.0.1"), OrigPort: port, Comm: "java"}

			start := time.Now()
			routed, wrapped, err := p.tryRouteToHTTPProxy(accepted, meta)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			if routed || wrapped == nil {
				t.Fatalf("want passthrough with wrapped conn, routed=%v wrapped=%v", routed, wrapped)
			}
			if elapsed > promptBound {
				t.Fatalf("passthrough took %s; want <%s (detection must exit at the first diverging byte, not wait out the window)", elapsed, promptBound)
			}

			// The peeked magic must be preserved: still readable from wrapped
			// without touching the (parked) client.
			if err := wrapped.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(magic))
			if _, err := io.ReadFull(wrapped, got); err != nil {
				t.Fatalf("reading peeked bytes back from wrapped conn: %v", err)
			}
			if !bytes.Equal(got, magic) {
				t.Fatalf("peeked bytes corrupted: got %x, want %x", got, magic)
			}
		})
	}
}

// TestTryRouteWellKnownPortByteIntegrity is the regression test for the old
// fast path dropping peeked bytes: non-HTTP traffic on 8080 must reach the raw
// passthrough with its prefix intact (pre-fix, the private bufio.Reader in
// HTTPProxy.HandleConnection swallowed it and the raw conn was returned).
func TestTryRouteWellKnownPortByteIntegrity(t *testing.T) {
	client, accepted := pipePair(t)
	defer client.Close()
	defer accepted.Close()
	payload := append([]byte{0xac, 0x00}, bytes.Repeat([]byte{0xaa}, 40)...)
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}

	p := &TCPProxy{}
	meta := &bpf.ConnectionMetadata{OrigIP: net.ParseIP("127.0.0.1"), OrigPort: 8080}
	start := time.Now()
	routed, wrapped, err := p.tryRouteToHTTPProxy(accepted, meta)
	elapsed := time.Since(start)
	if err != nil || routed {
		t.Fatalf("want passthrough, got routed=%v err=%v", routed, err)
	}
	if wrapped == nil {
		t.Fatal("wrapped conn required")
	}
	if elapsed > promptBound {
		t.Fatalf("passthrough took %s; want <%s", elapsed, promptBound)
	}

	if err := wrapped.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(wrapped, got); err != nil {
		t.Fatalf("reading from wrapped conn: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("prefix corrupted: got %x..., want %x...", got[:4], payload[:4])
	}
}

// TestDetectShortHTTPFirstFlight covers the other old-24-byte-peek bug: a
// complete HTTP request shorter than 24 bytes followed by a wait for the
// response used to stall detectProtocol for the whole read deadline. With
// progressive confirmation the request line is classified as soon as its
// method prefix is available.
func TestDetectShortHTTPFirstFlight(t *testing.T) {
	client, accepted := pipePair(t)
	defer client.Close()
	defer accepted.Close()
	if _, err := client.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err != nil { // 18 bytes, complete
		t.Fatal(err)
	}
	if err := accepted.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if got := detectProtocol(bufio.NewReader(accepted)); got != "http" {
		t.Fatalf("got %q, want http", got)
	}
	if elapsed := time.Since(start); elapsed > promptBound {
		t.Fatalf("classification took %s; want <%s", elapsed, promptBound)
	}
}

// TestTryRouteSilentClientPassthrough: a client that sends nothing must get
// passthrough, never a hang and never a killed connection. How long the proxy
// waits depends only on the destination-port hint: about firstByteWindow on
// non-HTTP ports (e.g. SMTP on 25: a server-speaks-first protocol waiting for
// a banner from the origin, which the proxy dials only after the sniff
// returns), but the full confirmWindow on conventional HTTP(S) ports, where
// slow-starting TLS/HTTP clients are common and server-first protocols are
// not. The 443 row also pins that tryRouteToHTTPProxy feeds OrigPort (not,
// say, the source port) into the budget.
func TestTryRouteSilentClientPassthrough(t *testing.T) {
	for _, tc := range []struct {
		port     uint16
		min, max time.Duration
	}{
		{25, firstByteWindow - 50*time.Millisecond, promptBound},
		{443, confirmWindow - 500*time.Millisecond, confirmWindow + 2*time.Second},
	} {
		t.Run(fmt.Sprintf("orig_port_%d", tc.port), func(t *testing.T) {
			client, accepted := pipePair(t)
			defer client.Close()
			defer accepted.Close()

			p := &TCPProxy{}
			meta := &bpf.ConnectionMetadata{OrigIP: net.ParseIP("127.0.0.1"), OrigPort: tc.port}

			start := time.Now()
			routed, wrapped, err := p.tryRouteToHTTPProxy(accepted, meta)
			elapsed := time.Since(start)
			if err != nil || routed || wrapped == nil {
				t.Fatalf("want (false, wrapped, nil), got (%v, %v, %v)", routed, wrapped, err)
			}
			if elapsed < tc.min || elapsed > tc.max {
				t.Fatalf("took %s; want between %s and %s", elapsed, tc.min, tc.max)
			}
		})
	}
}

// writeAfter writes data to c from a goroutine after d, and returns a func
// that waits for that goroutine to finish. Deferring the returned func after
// the Close defers makes it run first, so the write can neither race a closed
// conn nor outlive the test.
func writeAfter(c net.Conn, d time.Duration, data []byte) (wait func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(d)
		_, _ = c.Write(data)
	}()
	return func() { <-done }
}

// minimal TLS record: handshake, legacy version 0x0301, a few body bytes.
var clientHelloRecord = []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}

// TestSniffSlowClientHelloOnHTTPSPort is the recall guard: on conventional
// HTTP(S) ports the first-byte budget is the full confirmWindow (server-first
// protocols don't live there), so a TLS client that delays its ClientHello is
// still classified as HTTPS. The write lands at after 600ms, conservatively under the max window
// so it should be fine and not flaky in CI.
func TestSniffSlowClientHelloOnHTTPSPort(t *testing.T) {
	client, accepted := pipePair(t)
	defer client.Close()
	defer accepted.Close()
	start := time.Now() // before the writer starts, so elapsed >= the write delay by construction
	defer writeAfter(client, 600*time.Millisecond, clientHelloRecord)()

	br := bufio.NewReader(accepted)
	got := sniffProtocol(accepted, br, 443)
	elapsed := time.Since(start)
	if got != "tls" {
		t.Fatalf("got %q after %s, want tls (a slow ClientHello on 443 must still be classified)", got, elapsed)
	}
	if elapsed < 500*time.Millisecond {
		t.Fatalf("classified after %s, but the ClientHello is only written at 600ms", elapsed)
	}

	// Classification must not consume the ClientHello
	if err := accepted.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(clientHelloRecord))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("reading the ClientHello back after classification: %v", err)
	}
	if !bytes.Equal(buf, clientHelloRecord) {
		t.Fatalf("ClientHello corrupted: got %x, want %x", buf, clientHelloRecord)
	}
}

// TestSniffSlowClientHelloOffHTTPSPort documents the scope of the port hint,
// with no clock race: on a non-HTTP(S) port a silent client misses the 200ms
// first-byte window and sniffProtocol reports "" (relay raw).
func TestSniffSlowClientHelloOffHTTPSPort(t *testing.T) {
	client, accepted := pipePair(t)
	defer client.Close()
	defer accepted.Close()

	br := bufio.NewReader(accepted)
	if got := sniffProtocol(accepted, br, 12345); got != "" {
		t.Fatalf("got %q, want empty (no first byte within the 200ms window)", got)
	}

	if _, err := client.Write(clientHelloRecord); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(clientHelloRecord))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("reading late bytes after a sniff miss: %v", err)
	}
	if !bytes.Equal(buf, clientHelloRecord) {
		t.Fatalf("late bytes corrupted: got %x, want %x", buf, clientHelloRecord)
	}
}

// deadlineSpy records the most recent read deadline set on the conn.
type deadlineSpy struct {
	net.Conn
	lastReadDeadline time.Time
}

func (s *deadlineSpy) SetReadDeadline(t time.Time) error {
	s.lastReadDeadline = t
	return s.Conn.SetReadDeadline(t)
}

// TestSniffClearsReadDeadline checks if the read deadline is cleared
// before returning. A deadline left armed would kill the raw relay or
// the MITM handoff with an i/o timeout as soon as it  expires, up to
// confirmWindow after connect. The spy checks the clear directly instead
// of waiting out a window, so it is deterministic.
func TestSniffClearsReadDeadline(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write []byte // sent before the sniff; nil means a silent client
		want  string
	}{
		{"silent", nil, ""},
		{"tls", clientHelloRecord, "tls"},
		{"http", []byte("GET / HTTP/1.1\r\n\r\n"), "http"},
		{"unknown", []byte{'a', 'c', 0x00, 0x01}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, accepted := pipePair(t)
			defer client.Close()
			defer accepted.Close()
			if tc.write != nil {
				if _, err := client.Write(tc.write); err != nil {
					t.Fatal(err)
				}
			}
			spy := &deadlineSpy{Conn: accepted}
			if got := sniffProtocol(spy, bufio.NewReader(spy), 12345); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if !spy.lastReadDeadline.IsZero() {
				t.Fatalf("read deadline left armed at %v", spy.lastReadDeadline)
			}
		})
	}
}
