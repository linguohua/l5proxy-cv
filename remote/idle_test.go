package remote

import (
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"net"
	"testing"
	"time"
)

type idleTestConn struct{ net.Conn }

func (idleTestConn) ID() *stack.TransportEndpointID { return nil }
func (idleTestConn) CloseWrite() error              { return nil }
func (idleTestConn) CloseRead() error               { return nil }

func TestDisconnectClearsRequests(t *testing.T) {
	tnl := newTunnel(0, nil, &MgrConfig{TunnelCap: 1})
	a, b := net.Pipe()
	defer b.Close()
	old, err := tnl.reqq.alloc(idleTestConn{a})
	if err != nil {
		t.Fatal(err)
	}
	tnl.onDisconnected()
	if _, err := b.Write([]byte("x")); err == nil {
		t.Fatal("local connection remained open")
	}
	c, d := net.Pipe()
	defer c.Close()
	defer d.Close()
	next, err := tnl.reqq.alloc(idleTestConn{c})
	if err != nil {
		t.Fatal(err)
	}
	if old == next {
		t.Fatal("request reused while old reader may still run")
	}
	if err := tnl.reqq.free(old.idx, old.tag); err == nil {
		t.Fatal("stale reader freed replacement")
	}
}

func TestIdleRequestCloses(t *testing.T) {
	tnl := newTunnel(0, nil, &MgrConfig{TunnelCap: 1})
	tnl.idleTimeout = 25 * time.Millisecond
	a, b := net.Pipe()
	defer b.Close()
	r, _ := tnl.reqq.alloc(idleTestConn{a})
	done := make(chan struct{})
	go func() { r.proxy(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle reader did not exit")
	}
	if _, err := tnl.reqq.get(r.idx, r.tag); err == nil {
		t.Fatal("idle request not released")
	}
}
