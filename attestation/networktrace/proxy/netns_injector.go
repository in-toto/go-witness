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
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"

	"github.com/in-toto/go-witness/log"
	"golang.org/x/sys/unix"
)

// NetnsInjector injects a transparent proxy listener directly into ephemeral
// network namespaces using setns(2). Each injected listener binds the proxy
// port on loopback inside the target namespace and is serviced by the same
// connection handler as the host listener.
//
// Listeners are held open for the lifetime of the injector ("leak-until-exit"):
// the kernel cannot tear down a namespace while we hold a socket in it, which
// is exactly what keeps ephemeral CI namespaces alive long enough to proxy
// their traffic. Close (process exit) drops every fd at once and lets the
// kernel sweep the namespaces.
type NetnsInjector struct {
	proxy *TCPProxy
	port  uint16

	mu        sync.Mutex
	listeners map[uint32][]net.Listener // netns inode -> injected listeners

	// serveWg tracks the per-listener accept loops and the handlers they spawn,
	// so Close can wait for them before the main proxy calls recordWg.Wait().
	serveWg sync.WaitGroup
}

// NewNetnsInjector creates an injector that serves connections via the given
// proxy on the given port.
func NewNetnsInjector(p *TCPProxy, port uint16) *NetnsInjector {
	return &NetnsInjector{
		proxy:     p,
		port:      port,
		listeners: make(map[uint32][]net.Listener),
	}
}

// Inject sets up listeners inside the network namespace identified by its inode
// number. Callers treat this as a fatal, fail-closed condition.
func (in *NetnsInjector) Inject(ctx context.Context, netnsInum uint32) error {
	in.mu.Lock()
	if _, ok := in.listeners[netnsInum]; ok {
		in.mu.Unlock()
		return nil
	}
	in.mu.Unlock()

	nsPath, err := findNetnsPath(netnsInum)
	if err != nil {
		return fmt.Errorf("locate netns %d: %w", netnsInum, err)
	}

	v4, v6, err := in.listenInNetns(nsPath)
	if err != nil {
		return fmt.Errorf("inject listener into netns %d: %w", netnsInum, err)
	}

	listeners := make([]net.Listener, 0, 2)
	for _, l := range []net.Listener{v4, v6} {
		if l == nil {
			continue
		}
		listeners = append(listeners, l)
		ln := l
		in.serveWg.Go(func() { in.serve(ctx, ln) })
	}

	in.mu.Lock()
	in.listeners[netnsInum] = listeners
	in.mu.Unlock()

	log.Debugf("[networktrace] injected proxy listener into netns %d", netnsInum)
	return nil
}

// serve accepts connections on an injected listener and dispatches them to the
// shared connection handler. Both the accept loop and the spawned handlers are
// tracked by serveWg so Close can drain them before the proxy waits on its own
// recording WaitGroup.
func (in *NetnsInjector) serve(ctx context.Context, l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if errors.Is(err, net.ErrClosed) {
					return
				}
				log.Errorf("[networktrace] injected accept error: %v", err)
				continue
			}
		}
		c := conn
		in.serveWg.Go(func() {
			if err := in.proxy.HandleConnection(ctx, c); err != nil {
				log.Errorf("[networktrace] injected handle connection error: %v", err)
			}
		})
	}
}

// listenInNetns enters the target network namespace on a locked OS thread,
// binds loopback listeners, then restores the original namespace. The returned
// listeners belong to the caller's (host) process but accept traffic inside the
// target namespace.
func (in *NetnsInjector) listenInNetns(nsPath string) (v4 net.Listener, v6 net.Listener, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current (host) network namespace so we can return to it.
	origNs, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return nil, nil, fmt.Errorf("open current netns: %w", err)
	}
	defer origNs.Close()

	targetNs, err := os.Open(nsPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open target netns %s: %w", nsPath, err)
	}
	defer targetNs.Close()

	if err := unix.Setns(int(targetNs.Fd()), unix.CLONE_NEWNET); err != nil {
		return nil, nil, fmt.Errorf("setns into target: %w", err)
	}
	// Always attempt to restore the original namespace before returning.
	defer func() {
		if rerr := unix.Setns(int(origNs.Fd()), unix.CLONE_NEWNET); rerr != nil {
			err = errors.Join(err, fmt.Errorf("restore original netns: %w", rerr))
		}
	}()

	lc := net.ListenConfig{}
	v4, err = lc.Listen(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", in.port))
	if err != nil {
		return nil, nil, fmt.Errorf("listen v4 in netns: %w", err)
	}

	v6, err = lc.Listen(context.Background(), "tcp", fmt.Sprintf("[::1]:%d", in.port))
	if err != nil {
		// IPv6 may be disabled in the namespace; v4 alone is acceptable.
		log.Debugf("[networktrace] v6 listen in netns failed (continuing v4-only): %v", err)
		v6 = nil
	}

	return v4, v6, nil
}

// Close drops all injected listeners, releasing the namespace references, and
// waits for all accept loops and in-flight injected handlers to finish. It must
// be called before the main proxy closes the connection channel so injected
// handlers never send on a closed channel.
func (in *NetnsInjector) Close() {
	in.mu.Lock()
	for _, ls := range in.listeners {
		for _, l := range ls {
			_ = l.Close()
		}
	}
	in.listeners = make(map[uint32][]net.Listener)
	in.mu.Unlock()

	in.serveWg.Wait()
}

// findNetnsPath resolves a network-namespace inode number to a procfs path that
// can be opened and passed to setns. It scans /proc/<pid>/ns/net entries; any
// task currently living in the target namespace yields a usable handle.
func findNetnsPath(netnsInum uint32) (string, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", fmt.Errorf("read /proc: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name[0] < '0' || name[0] > '9' {
			continue
		}
		p := fmt.Sprintf("/proc/%s/ns/net", name)
		var st unix.Stat_t
		if err := unix.Stat(p, &st); err != nil {
			continue
		}
		if uint32(st.Ino) == netnsInum {
			return p, nil
		}
	}
	return "", fmt.Errorf("no task found in netns %d", netnsInum)
}
