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
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/in-toto/go-witness/attestation/networktrace/bpf"
	"github.com/in-toto/go-witness/attestation/networktrace/types"
	"github.com/in-toto/go-witness/log"
)

// TCPProxy implements a transparent TCP proxy
type TCPProxy struct {
	maps          *bpf.Maps
	port          uint16
	proxyBindIPv4 string
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
}

// NewTCPProxy creates a new transparent TCP proxy
// The transparency comes from bpf which routes traffic to the proxy
func NewTCPProxy(maps *bpf.Maps, port uint16, proxyBindIPv4 string, enableHTTP bool, payloadConfig types.PayloadConfig, connChan chan types.Connection) *TCPProxy {
	return &TCPProxy{
		maps:           maps,
		port:           port,
		proxyBindIPv4:  proxyBindIPv4,
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
						log.Errorf("IPv6 accept error: %v", err)
						continue
					}
				}
				go func() {
					if err := p.HandleConnection(ctx, conn); err != nil {
						log.Errorf("Handle IPv6 connection error: %v", err)
					}
				}()
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

	// Signal that we're ready to accept connections (both IPv4 and IPv6 are set up)
	if ready != nil {
		close(ready)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					log.Errorf("Accept error: %v", err)
					continue
				}
			}

			go func() {
				if err := p.HandleConnection(ctx, conn); err != nil {
					log.Errorf("Handle connection error: %v", err)
				}
			}()
		}
	}()

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

	file, err := tcpConn.File()
	if err != nil {
		clientConn.Close()
		return fmt.Errorf("get file descriptor: %w", err)
	}
	defer file.Close()

	log.Infof("[TCP PROXY] Handling new connection from %s to %s", clientConn.RemoteAddr(), clientConn.LocalAddr())

	sockCookie, err := bpf.GetSocketCookie(int(file.Fd()))
	if err != nil {
		clientConn.Close()
		return fmt.Errorf("get socket cookie: %w", err)
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

	// This defer is placed here to allow easier addition of http proxy code later
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

	// Buffers to accumulate data for each direction
	// Recording happens async after bidirectional copy
	var clientToServerBuf bytes.Buffer
	var serverToClientBuf bytes.Buffer

	copyErr := p.bidirectionalCopy(ctx, conn, &clientToServerBuf, &serverToClientBuf)

	p.recordWg.Add(1)
	go func() {
		defer p.recordWg.Done()
		p.recordConnection(metadata, clientToServerBuf.Bytes(), serverToClientBuf.Bytes(), copyErr)
	}()

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

func (p *TCPProxy) getConnectionMetadata(sockCookie uint64, isIPv6 bool) (*bpf.ConnectionMetadata, error) {
	if isIPv6 {
		origVal6, err := p.maps.LookupOrigDstV6(sockCookie)
		if err != nil {
			return nil, fmt.Errorf("lookup IPv6 original destination: %w", err)
		}
		return origVal6.ToConnectionMetadata(sockCookie), nil
	}

	origVal4, err := p.maps.LookupOrigDst(sockCookie)
	if err != nil {
		return nil, fmt.Errorf("lookup IPv4 original destination: %w", err)
	}
	return origVal4.ToConnectionMetadata(sockCookie), nil
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
// we ignore the context here since we want to fully drain both directions, but context is still passed for future use
func (p *TCPProxy) bidirectionalCopy(_ context.Context, conn *TCPConn, clientToServerBuf, serverToClientBuf *bytes.Buffer) error {
	errChan := make(chan error, 2)

	// Client -> Server
	go func() {
		_, err := io.Copy(io.MultiWriter(conn.ServerConn, clientToServerBuf), conn.ClientConn)
		errChan <- err
	}()

	// Server -> Client
	go func() {
		_, err := io.Copy(io.MultiWriter(conn.ClientConn, serverToClientBuf), conn.ServerConn)
		errChan <- err
	}()

	err1 := <-errChan

	conn.ClientConn.(*net.TCPConn).CloseRead()
	conn.ServerConn.(*net.TCPConn).CloseWrite()

	err2 := <-errChan

	if err1 != nil && err1 != io.EOF {
		return err1
	}
	if err2 != nil && err2 != io.EOF {
		return err2
	}
	return nil
}
