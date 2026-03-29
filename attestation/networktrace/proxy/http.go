//go:build linux

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/in-toto/go-witness/attestation/networktrace/bpf"
	"github.com/in-toto/go-witness/attestation/networktrace/types"
	"github.com/in-toto/go-witness/log"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const metadataContextKey contextKey = "witness-connection-metadata"

// SuppressConnectResponseWriter suppresses the "HTTP/1.1 200 Connection Established" response
// that goproxy sends for CONNECT requests. In transparent mode, the client sends TLS ClientHello
// and doesn't except an HTTP/1.0 200 OK response, so we need to eat that response.
type SuppressConnectResponseWriter struct {
	net.Conn
	br *bufio.Reader // Existing buffered reader with peeked TLS data
}

// Header returns an empty header map
func (e *SuppressConnectResponseWriter) Header() http.Header {
	return http.Header{}
}

// Read reads from the buffered reader to ensure peeked data is consumed first
func (e *SuppressConnectResponseWriter) Read(p []byte) (int, error) {
	n, err := e.br.Read(p)
	return n, err
}

// // Write passes through the actual data (TLS handshake bytes) to the client
// func (e *SuppressConnectResponseWriter) Write(data []byte) (int, error) {
// 	// Only eat the CONNECT response, let everything else through
// 	if bytes.Equal(data, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
// 		return len(data), nil // Suppress the HTTP OK response for transparent proxying
// 	}
// 	return e.Conn.Write(data)
// }

// Write passes through the actual data (TLS handshake bytes) to the client
func (e *SuppressConnectResponseWriter) Write(data []byte) (int, error) {
	// FIX: Use a more robust check.
	// goproxy standard response is "HTTP/1.0 200 OK\r\n\r\n"
	// But we should catch variations like HTTP/1.1 or partial writes.

	// Check if it looks like an HTTP 200 OK response
	if len(data) >= 12 && (bytes.HasPrefix(data, []byte("HTTP/1.0 200")) || bytes.HasPrefix(data, []byte("HTTP/1.1 200"))) {
		log.Infof("[Suppressor] Successfully suppressed HTTP 200 OK response (%d bytes)", len(data))
		return len(data), nil // Swallow the bytes, return success
	}

	// Debug log to catch if we are missing it
	if len(data) < 100 && bytes.Contains(data, []byte("HTTP/")) {
		log.Warnf("[Suppressor] WARNING: Leaking potential HTTP header to TLS client: %q", string(data))
	}

	return e.Conn.Write(data)
}

func (e *SuppressConnectResponseWriter) WriteHeader(statusCode int) {
	// no-op
}

// Hijack implements http.Hijacker interface, required by goproxy for CONNECT requests
func (e *SuppressConnectResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	// Reuse the existing buffered reader (br) which contains peeked data
	return e, bufio.NewReadWriter(e.br, bufio.NewWriter(e)), nil
}

// HTTPProxy handles HTTP/HTTPS traffic using goproxy
type HTTPProxy struct {
	proxy *goproxy.ProxyHttpServer
	caMgr *CAManager

	connectionChan chan types.Connection
	payloadConfig  types.PayloadConfig

	// WaitGroup to track in-flight connection recordings
	recordWg sync.WaitGroup
}

type goProxyUserData struct {
	requestBody  []byte
	connRecorder *ConnectionRecorder
}

// NewHTTPProxy creates a new HTTP/HTTPS proxy
func NewHTTPProxy(caMgr *CAManager, payloadConfig types.PayloadConfig, connChan chan types.Connection, skipVerify bool) *HTTPProxy {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true

	httpProxy := &HTTPProxy{
		proxy:          proxy,
		caMgr:          caMgr,
		connectionChan: connChan,
		payloadConfig:  payloadConfig,
	}

	httpProxy.setupHandlers(skipVerify)

	return httpProxy
}

// Wait blocks until all in-flight HTTP recordings have completed
func (h *HTTPProxy) Wait() {
	h.recordWg.Wait()
}

// Serving self generated certificates for MITM
func configureCert(ca *tls.Certificate) {
	goproxy.OkConnect = &goproxy.ConnectAction{
		Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(ca)}

	goproxy.MitmConnect = &goproxy.ConnectAction{
		Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(ca)}

	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{
		Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(ca)}

	goproxy.RejectConnect = &goproxy.ConnectAction{
		Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(ca)}
}

// setupHandlers configures the proxy handlers
func (h *HTTPProxy) setupHandlers(skipVerify bool) {
	h.proxy.Tr = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipVerify,
		},

		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if h.caMgr != nil {
		h.proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			log.Infof("Handling CONNECT request for host: %s", host)
			// Extract metadata from request context and store in ProxyCtx for later use
			if metadata, ok := ctx.Req.Context().Value(metadataContextKey).(*goProxyUserData); ok {
				log.Infof("[Proxy] Found metadata in CONNECT context for %s", host)
				ctx.UserData = metadata
			} else {
				log.Warnf("[Proxy] No metadata in CONNECT context for %s", host)
			}
			return goproxy.MitmConnect, host
		})

		configureCert(h.caMgr.GetCA())
	}

	h.proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		log.Infof("HTTP Request: %s %s %s", req.Method, req.Host, req.URL.Path)

		// Try to get metadata from request context (set in HandleConnection)
		// or from ctx.UserData as fallback
		var metadata *goProxyUserData
		if md, ok := req.Context().Value(metadataContextKey).(*goProxyUserData); ok {
			metadata = md
			// Store in UserData for response handler
			ctx.UserData = metadata
			log.Infof("[Proxy] Found metadata in Request context")
		} else if ctx.UserData != nil {
			if md, ok := ctx.UserData.(*goProxyUserData); ok {
				metadata = md
				log.Infof("[Proxy] Found metadata in ctx.UserData")
			}
		} else {
			log.Warnf("[Proxy] No metadata found for request %s %s", req.Method, req.URL.Path)
		}

		if metadata != nil {
			// Record the request body and pass it in context
			if req.Body != nil {
				bodyBytes, err := io.ReadAll(req.Body)
				if err != nil {
					log.Errorf("Read request body error: %v", err)
				} else {
					// create a copy of bodyBytes as NewBuffer will use the slice directly
					bodyBytesCopy := make([]byte, len(bodyBytes))
					copy(bodyBytesCopy, bodyBytes)

					// Restore the io.ReadCloser to its original state
					req.Body = io.NopCloser(bytes.NewBuffer(bodyBytesCopy))
				}
				// Add the body to the ctx.UserData
				metadata.requestBody = bodyBytes
			}

		} else {
			log.Errorf("metadata is nil, expected to be present")
		}

		return req, nil
	})

	h.proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp != nil {
			log.Infof("HTTP Response: %s %d %s", resp.Request.Host, resp.StatusCode, resp.Status)

			var goProxyData *goProxyUserData
			if ctx.UserData != nil {
				if md, ok := ctx.UserData.(*goProxyUserData); ok {
					goProxyData = md
				}
			}

			if goProxyData != nil {
				// Read response body
				var respBodyBytes []byte
				if resp.Body != nil {
					// TODO: Currently all is being buffered in the memory, implement some disk caching
					// or io.TeeWriter for just calculating hash. Technically, proxy allows to record the
					// entire payload, so that should be supported in case response is huge (iso, etc.)
					bodyBytes, err := io.ReadAll(resp.Body)
					if err != nil {
						log.Errorf("Read response body error: %v", err)
					} else {
						respBodyBytes = make([]byte, len(bodyBytes))
						copy(respBodyBytes, bodyBytes)
						// Restore the io.ReadCloser to its original state
						resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
					}
				}

				// cloning is required to prevent concurrent map read/write panic
				requestHeader := cloneHeaders(ctx.Req.Header)
				responseHeader := cloneHeaders(resp.Header)

				// Record the exchange asynchronously
				// Track with WaitGroup so we can wait for all recordings to complete
				h.recordWg.Go(func() {
					goProxyData.connRecorder.RecordHTTPExchange(ctx.Req, goProxyData.requestBody, resp, respBodyBytes, requestHeader, responseHeader)
					result := goProxyData.connRecorder.Finish()
					log.Infof("Recorded HTTP connection: %s", result.ID)
					// Send the recorded connection to the channel
					h.connectionChan <- result
				})
			} else {
				log.Errorf("goProxyData or metadata is nil, expected to be present")
			}
		}
		return resp
	})
}

// HandleConnection handles an HTTP/HTTPS connection through goproxy
func (h *HTTPProxy) HandleConnection(conn net.Conn, metadata *bpf.ConnectionMetadata) error {
	// Create buffered reader for protocol detection
	br := bufio.NewReader(conn)
	return h.HandleBufferedConnection(conn, br, metadata)
}

// HandleBufferedConnection handles a connection with an existing buffered reader.
// This allows the caller (e.g. TCPProxy) to peek at bytes for protocol detection
// and then hand off the connection without losing buffered data.
func (h *HTTPProxy) HandleBufferedConnection(conn net.Conn, br *bufio.Reader, metadata *bpf.ConnectionMetadata) error {
	// Detect protocol (HTTP vs TLS)
	proto, err := detectProtocol(br)
	if err != nil {
		return fmt.Errorf("detect protocol: %w", err)
	}

	// TODO: There is a race condition between the TCP proxy terminating and the HTTP request, response pool draining
	// This can be mitigated by adding a wait group here or some other better place. As we rely on goproxy package, it
	// might be that we can't get that fine control, so hooking higher might be required. Also, making sure that we don't
	// block indefinitely using a wg
	switch proto {
	case "tls":
		// HTTPS traffic - parse SNI and create synthetic CONNECT request for goproxy to MITM this TCP connection
		log.Infof("Detected TLS traffic: %s", metadata)
		return h.handleTLS(conn, br, metadata)

	case "http":
		// Plain HTTP traffic - handle normally
		log.Infof("Detected HTTP traffic: %s", metadata)
		return h.handleHTTP(conn, br, metadata)

	default:
		return fmt.Errorf("unsupported protocol: %s", proto)
	}
}

// handleTLS handles HTTPS traffic with transparent MITM
func (h *HTTPProxy) handleTLS(conn net.Conn, br *bufio.Reader, metadata *bpf.ConnectionMetadata) error {
	// Parse ClientHello from the existing buffered reader (includes SNI, versions, cipher suites)
	parsedHello, err := parseClientHelloFromBufferedReader(br)
	if err != nil {
		log.Errorf("[TLS] Warning: Failed to parse ClientHello: %v", err)
	}

	var sni string
	if parsedHello != nil {
		sni = parsedHello.SNI
	}

	if sni == "" {
		// No SNI - fall back to using IP:port
		log.Errorf("[TLS] Warning: No SNI found, using IP address for CONNECT")
		sni = metadata.OrigIP.String()
	}

	// Create synthetic CONNECT request for goproxy
	target := fmt.Sprintf("%s:%d", sni, metadata.OrigPort)
	connectReq := &http.Request{
		Method: "CONNECT",
		URL: &url.URL{
			Host: target,
		},
		Host:       target,
		Header:     make(http.Header),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		RemoteAddr: conn.RemoteAddr().String(),
	}

	recorder := NewConnectionRecorder(metadata, "https", h.payloadConfig)
	recorder.SetHostname(sni)
	recorder.SetIntercepted(true)
	// We need tls.ConnectionState to record actual negotiated parameters after handshake
	// Needs exploring goproxy internals to get that info - for now, we skip it
	// recorder.RecordTLSInfo(nil, sni)

	// Record ClientHello info (what client supports/offers)
	if parsedHello != nil && parsedHello.ClientHello != nil {
		recorder.RecordClientHelloInfo(parsedHello.ClientHello)
	}

	goProxyUserData := &goProxyUserData{
		connRecorder: recorder,
	}

	ctx := context.WithValue(context.Background(), metadataContextKey, goProxyUserData)
	connectReq = connectReq.WithContext(ctx)

	// Use EatConnectResponseWriter to suppress "HTTP/1.1 200" response
	// Pass both the connection and the buffered reader so Hijack() can reuse it
	writer := &SuppressConnectResponseWriter{
		Conn: conn,
		br:   br,
	}

	// Pass to goproxy - it will hijack the connection and spawn a goroutine for MITM
	// We can return immediately - the connection ownership is transferred to goproxy
	h.proxy.ServeHTTP(writer, connectReq)
	return nil
}

// handleHTTP handles plain HTTP traffic
func (h *HTTPProxy) handleHTTP(conn net.Conn, br *bufio.Reader, metadata *bpf.ConnectionMetadata) error {
	transparentHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Since we are intercepting transparently, the request comes in as:
		// GET /foo HTTP/1.1
		// Host: example.com
		//
		// goproxy expects:
		// GET http://example.com/foo HTTP/1.1

		if r.URL.Scheme == "" {
			r.URL.Scheme = "http" // Assume HTTP since we are in handleHTTP
		}
		if r.URL.Host == "" {
			r.URL.Host = r.Host // Use the Host header
		}

		h.proxy.ServeHTTP(w, r)
	})

	server := &http.Server{
		Handler: transparentHandler,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			recorder := NewConnectionRecorder(metadata, "http", h.payloadConfig)
			goProxyUserData := &goProxyUserData{
				connRecorder: recorder,
			}
			return context.WithValue(ctx, metadataContextKey, goProxyUserData)
		},
	}

	// Wrap connection with buffered reader
	bufConn := &bufferedConn{Conn: conn, br: br}
	err := server.Serve(&singleConnListener{conn: bufConn})

	// server.Serve() returns io.EOF when the listener is closed (normal for single connection)
	// or http.ErrServerClosed when explicitly closed - both are success cases
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, io.EOF) {
		return fmt.Errorf("serve HTTP connection: %w", err)
	}

	return nil
}

// singleConnListener is a net.Listener that returns a single connection then EOF
type singleConnListener struct {
	conn net.Conn
	once sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() {
		c = l.conn
	})
	if c != nil {
		return c, nil
	}
	return nil, io.EOF
}

func (l *singleConnListener) Close() error {
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
