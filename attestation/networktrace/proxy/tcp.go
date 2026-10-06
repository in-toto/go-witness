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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/in-toto/go-witness/attestation/networktrace/bpf"
	"github.com/in-toto/go-witness/attestation/networktrace/types"
	"github.com/in-toto/go-witness/log"
)

// TCPProxy implements a transparent TCP proxy
type TCPProxy struct {
	maps          *bpf.Maps
	httpProxy     *HTTPProxy
	port          uint16
	proxyBindIPv4 string
	enableHTTP    bool
	payloadConfig types.PayloadConfig

	// Channel for collecting completed connections
	ConnectionChan chan types.Connection

	// WaitGroup to track in-flight connection recordings
	recordWg sync.WaitGroup
}

// TCPConn represents a tracked TCP connection
type TCPConn struct {
	ClientConn net.Conn
	ServerConn net.Conn
	Metadata   *bpf.ConnectionMetadata
	StartTime  time.Time

	isForceClosed atomic.Bool
}

// NewTCPProxy creates a new transparent TCP proxy
// The transparency comes from bpf which routes traffic to the proxy
func NewTCPProxy(maps *bpf.Maps, httpProxy *HTTPProxy, port uint16, proxyBindIPv4 string, enableHTTP bool, payloadConfig types.PayloadConfig, connChan chan types.Connection) *TCPProxy {
	return &TCPProxy{
		maps:           maps,
		httpProxy:      httpProxy,
		port:           port,
		proxyBindIPv4:  proxyBindIPv4,
		enableHTTP:     httpProxy != nil && enableHTTP,
		payloadConfig:  payloadConfig,
		ConnectionChan: connChan,
	}
}

// Start starts the TCP proxy server
// The ready channel is closed once the proxy is listening and ready to accept connections.
// Pass nil if you don't need to wait for readiness.
func (p *TCPProxy) Start(ctx context.Context, ready chan<- struct{}) error {
	// Listen on IPv6 localhost (::1)
	// TODO: Make this configurable as well
	addr := fmt.Sprintf("[::1]:%d", p.port)
	listenerV6, err := net.Listen("tcp", addr)
	if err != nil {
		log.Errorf("IPv6 listen on %s failed: %v", addr, err)
		return fmt.Errorf("listen on %s: %w", addr, err)
	} else {
		log.Infof("TCP proxy listening on %s (IPv6)", addr)
		go func() {
			for {
				conn, err := listenerV6.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						return
					default:
						if errors.Is(err, net.ErrClosed) {
							return
						}

						log.Errorf("IPv6 accept error: %v", err)
						continue
					}
				}
				p.recordWg.Go(func() {
					if err := p.HandleConnection(ctx, conn); err != nil {
						log.Errorf("Handle IPv6 connection error: %v", err)
					}
				})
			}
		}()
	}

	// Listen on IPv4 localhost
	addrV4 := fmt.Sprintf("%s:%d", p.proxyBindIPv4, p.port)
	listener, err := net.Listen("tcp", addrV4)
	if err != nil {
		if listenerV6 != nil {
			listenerV6.Close()
		}
		return fmt.Errorf("listen on %s: %w", addrV4, err)
	}

	log.Infof("TCP proxy listening on %s (IPv4)", addrV4)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					if errors.Is(err, net.ErrClosed) {
						return
					}

					log.Errorf("Accept error: %v", err)
					continue
				}
			}

			p.recordWg.Go(func() {
				if err := p.HandleConnection(ctx, conn); err != nil {
					log.Errorf("Handle connection error: %v", err)
				}
			})
		}
	}()

	// Signal that we're ready to accept connections (both IPv4 and IPv6 are set up)
	if ready != nil {
		close(ready)
	}

	// Wait for context cancellation
	<-ctx.Done()
	log.Infof("TCP proxy shutting down")

	if listener != nil {
		listener.Close()
	}
	if listenerV6 != nil {
		listenerV6.Close()
	}

	// Wait for all in-flight connection recordings to complete
	// This ensures all sends to ConnectionChan are done before we return
	p.recordWg.Wait()
	if p.enableHTTP {
		p.httpProxy.Wait()
	}

	log.Infof("TCP proxy shutdown complete: all recordings finished")

	return nil
}

// HandleConnection handles a single TCP connection
func (p *TCPProxy) HandleConnection(ctx context.Context, clientConn net.Conn) error {
	tcpConn, ok := clientConn.(*net.TCPConn)
	if !ok {
		clientConn.Close()
		return fmt.Errorf("not a TCP connection")
	}

	// Use SyscallConn().Control() instead of tcpConn.File() to access the raw fd.
	// tcpConn.File() calls dup(2) which puts the original socket into blocking mode,
	// making SetDeadline and Close ineffective and causing deadlocks during shutdown.
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		clientConn.Close()
		return fmt.Errorf("get syscall conn: %w", err)
	}

	var sockCookie uint64
	var cookieErr error
	if err := rawConn.Control(func(fd uintptr) {
		sockCookie, cookieErr = bpf.GetSocketCookie(int(fd))
	}); err != nil {
		clientConn.Close()
		return fmt.Errorf("raw conn control: %w", err)
	}

	log.Infof("[TCP PROXY] Handling new connection from %s to %s", clientConn.RemoteAddr(), clientConn.LocalAddr())

	if cookieErr != nil {
		clientConn.Close()
		return fmt.Errorf("get socket cookie: %w", cookieErr)
	}

	log.Infof("[TCP PROXY] Got socket cookie: %d (0x%x)", sockCookie, sockCookie)

	isIPv6 := false
	if tcpAddr, ok := clientConn.LocalAddr().(*net.TCPAddr); ok {
		isIPv6 = tcpAddr.IP.To4() == nil
	}

	metadata, err := p.getConnectionMetadata(sockCookie, isIPv6)
	if err != nil {
		clientConn.Close()
		return fmt.Errorf("get connection metadata: %w", err)
	}

	log.Infof("New connection: %s (cookie=%d/0x%x)", metadata, sockCookie, sockCookie)

	// Try HTTP/HTTPS handling if enabled
	if p.enableHTTP {
		routed, wrappedConn, err := p.tryRouteToHTTPProxy(clientConn, metadata)
		if err != nil {
			log.Warnf("[TCP PROXY] HTTP proxy routing failed: %v", err)
		}
		if routed {
			return nil
		}
		// Use the wrapped connection (preserves any peeked bytes)
		if wrappedConn != nil {
			clientConn = wrappedConn
		}
	}

	defer clientConn.Close()

	serverConn, err := p.connectToOriginalDestination(metadata)
	if err != nil {
		return fmt.Errorf("connect to original destination: %w", err)
	}
	defer serverConn.Close()

	conn := &TCPConn{
		ClientConn: clientConn,
		ServerConn: serverConn,
		Metadata:   metadata,
		StartTime:  time.Now(),
	}

	// Give in-flight data 3 seconds to drain before forcefully unblocking io.Copy
	const gracePeriod = 3 * time.Second

	stop := context.AfterFunc(ctx, func() {
		conn.isForceClosed.Store(true)
		deadline := time.Now().Add(gracePeriod)

		// not closing the socket immediately, just telling the OS to return
		// an i/o timeout error if operations haven't finished by the deadline.
		_ = clientConn.SetDeadline(deadline)
		_ = serverConn.SetDeadline(deadline)

		// fallback: actually close the connection slightly after the deadline
		// just in case a weird socket state ignores the deadline.
		time.AfterFunc(gracePeriod+time.Second, func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})
	})

	// If bidirectionalCopy finishes naturally before the shutdown OR before
	// the grace period ends, this cancels the AfterFunc timer so it doesn't leak.
	defer stop()

	// Buffers to accumulate data for each direction
	// Recording happens async after bidirectional copy
	var clientToServerBuf bytes.Buffer
	var serverToClientBuf bytes.Buffer

	copyErr := p.bidirectionalCopy(ctx, conn, &clientToServerBuf, &serverToClientBuf)
	if copyErr != nil {
		if conn.isForceClosed.Load() {
			log.Debugf("[TCP PROXY] Connection drained and closed intentionally")
			copyErr = nil
		} else if errors.Is(copyErr, io.EOF) || errors.Is(copyErr, net.ErrClosed) {
			copyErr = nil
		}
	}

	p.recordWg.Go(func() {
		p.recordConnection(metadata, clientToServerBuf.Bytes(), serverToClientBuf.Bytes(), copyErr)
	})

	return copyErr
}

// recordConnection records the connection data and sends to channel
func (p *TCPProxy) recordConnection(metadata *bpf.ConnectionMetadata, c2sData, s2cData []byte, connErr error) {
	recorder := NewConnectionRecorder(metadata, "tcp", p.payloadConfig)

	// Always record both directions, even if empty - a connection with 0 bytes
	// transferred is still a meaningful security event (e.g., port probing, reconnaissance)
	recorder.RecordTCPPayloadDirect(DirectionClientToServer, c2sData)
	recorder.RecordTCPPayloadDirect(DirectionServerToClient, s2cData)

	if connErr != nil {
		recorder.SetError(connErr)
	}

	result := recorder.Finish()

	p.ConnectionChan <- result

	log.Infof("Connection recorded: %s, sent=%d, received=%d", result.ID, result.BytesSent, result.BytesReceived)
}

const (
	// firstByteWindow is the default patience for a client's very first
	// byte before relaying transparently. Apart from known HTTP(s) port,
	// silent clients are overwhelmingly server-first protocols (SMTP, FTP,
	// MySQL) or idle pre-connects, and the origin is only dialed after this
	// sniff returns so they must not be charged the full confirmation
	// budget.
	firstByteWindow = 200 * time.Millisecond

	// confirmWindow bounds the protocol confirmation peeks once a first byte
	// has arrived (i.e. the client speaks first). Both supported protocols
	// are client-speaks-first, so only a slow or paused first flight ever
	// uses this budget; unknown protocols exit at their first diverging
	// byte. It must never be unbounded: a client that sends a short header
	// and then waits for a reply (e.g. the Gradle worker protocol) would
	// otherwise deadlock against an original destination the proxy has not
	// dialed yet.
	confirmWindow = 2 * time.Second
)

// firstByteBudget returns how long to wait for a client's first byte. The
// destination port is only a timing hint, classification stays purely
// content-based. On conventional HTTP(S) ports server-first protocols do not
// live and slow-starting TLS/HTTP clients are common, so patience is
// the full confirmWindow there; everywhere else it is firstByteWindow. Any
// bounded window can still be outwaited deliberately; the hint only restores
// recall for benign slow starters.
func firstByteBudget(port uint16) time.Duration {
	switch port {
	// TODO: After adding a model to skip localhost connections, it should be discussed
	// whether requests to these ports should always be MITMed as they are common
	// HTTP(S) ports. That would prevent a slow client from avoiding the protocol detection window.
	case 80, 443, 8080, 8443:
		return confirmWindow
	}
	return firstByteWindow
}

// sniffProtocol peeks the first byte for client-first protocols (HTPP, TLS) and if it's server first,
// it's out of scope of interception. After reading the first byte with the first byte budget, it parses
// the client connection to classify the protocol.
func sniffProtocol(conn net.Conn, br *bufio.Reader, port uint16) string {
	_ = conn.SetReadDeadline(time.Now().Add(firstByteBudget(port)))
	if _, err := br.Peek(1); err != nil {
		_ = conn.SetReadDeadline(time.Time{})
		return "" // silent client: relay transparently
	}

	// A first byte arrived, so the client speaks first: only slow or paused
	// first flights ever spend this budget.
	_ = conn.SetReadDeadline(time.Now().Add(confirmWindow))
	proto := detectProtocol(br)
	_ = conn.SetReadDeadline(time.Time{})
	return proto
}

// tryRouteToHTTPProxy sniffs the connection's first bytes to decide whether
// it is HTTP, TLS, or the HTTP/2 cleartext preface, and hands HTTP/TLS traffic
// to the HTTP MITM proxy.
// Returns (true, nil, nil) if the connection was handed off to the HTTP proxy.
// Returns (false, wrappedConn, nil) if the connection should be handled as
// raw TCP; wrappedConn preserves any bytes buffered while sniffing.
// Unknown protocols, silent clients, truncated first flights, and clients
// whose first bytes miss the first-byte budget all take the passthrough path:
// the proxy never holds a connection hostage waiting for classification
// evidence it may never get.
func (p *TCPProxy) tryRouteToHTTPProxy(clientConn net.Conn, metadata *bpf.ConnectionMetadata) (bool, net.Conn, error) {
	br := bufio.NewReader(clientConn)
	wrapped := &bufferedConn{Conn: clientConn, br: br}

	switch proto := sniffProtocol(clientConn, br, metadata.OrigPort); proto {
	case "tls", "http":
		log.Infof("[TCP PROXY] Detected %s protocol on port %d, routing to HTTP proxy", proto, metadata.OrigPort)
		if err := p.httpProxy.HandleBufferedConnection(clientConn, br, proto, metadata); err != nil {
			return false, wrapped, fmt.Errorf("HTTP proxy (%s): %w", proto, err)
		}
		return true, nil, nil
	case "h2c":
		// TODO: goproxy http/2 support needs to be verified
		log.Infof("[TCP PROXY] HTTP/2 cleartext preface on port %d: not MITM-able, relaying raw", metadata.OrigPort)
	default:
		log.Infof("[TCP PROXY] No HTTP/TLS evidence on port %d, relaying raw (unparsed)", metadata.OrigPort)
	}
	return false, wrapped, nil
}

func (p *TCPProxy) getConnectionMetadata(sockCookie uint64, isIPv6 bool) (*bpf.ConnectionMetadata, error) {
	if isIPv6 {
		metadata, err := p.maps.LookupOrigDstV6(sockCookie)
		if err != nil {
			return nil, fmt.Errorf("lookup IPv6 original destination: %w", err)
		}
		return metadata, nil
	}

	metadata, err := p.maps.LookupOrigDst(sockCookie)
	if err != nil {
		return nil, fmt.Errorf("lookup IPv4 original destination: %w", err)
	}
	return metadata, nil
}

func (p *TCPProxy) connectToOriginalDestination(metadata *bpf.ConnectionMetadata) (net.Conn, error) {
	var target string
	if metadata.OrigIP.To4() == nil {
		target = fmt.Sprintf("[%s]:%d", metadata.OrigIP, metadata.OrigPort)
	} else {
		target = fmt.Sprintf("%s:%d", metadata.OrigIP, metadata.OrigPort)
	}
	return (&net.Dialer{Timeout: 10 * time.Second}).Dial("tcp", target)
}

// bidirectionalCopy copies data between client and server connections
func (p *TCPProxy) bidirectionalCopy(_ context.Context, conn *TCPConn, clientToServerBuf, serverToClientBuf *bytes.Buffer) error {
	errChan := make(chan error, 2)

	// Client -> Server
	go func() {
		_, err := io.Copy(io.MultiWriter(conn.ServerConn, clientToServerBuf), conn.ClientConn)

		if tcpConn := underlyingTCPConn(conn.ServerConn); tcpConn != nil {
			_ = tcpConn.CloseWrite() // Send a FIN to the server to signal that the client is done sending data
		}
		errChan <- err
	}()

	// Server -> Client
	go func() {
		_, err := io.Copy(io.MultiWriter(conn.ClientConn, serverToClientBuf), conn.ServerConn)

		if tcpConn := underlyingTCPConn(conn.ClientConn); tcpConn != nil {
			_ = tcpConn.CloseWrite() // Send a FIN to the client to signal that the server is done sending data
		}
		errChan <- err
	}()

	err1 := <-errChan
	err2 := <-errChan

	if err1 != nil && !errors.Is(err1, io.EOF) {
		return err1
	}
	if err2 != nil && !errors.Is(err2, io.EOF) {
		return err2
	}
	return nil
}

// bufferedConn wraps a net.Conn with a bufio.Reader so that
// any data already peeked/buffered is consumed before reading
// from the underlying connection.
type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.br.Read(p)
}

// underlyingTCPConn unwraps wrapper types to find the underlying *net.TCPConn.
func underlyingTCPConn(c net.Conn) *net.TCPConn {
	switch v := c.(type) {
	case *net.TCPConn:
		return v
	case *bufferedConn:
		return underlyingTCPConn(v.Conn)
	default:
		return nil
	}
}
