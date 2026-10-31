package remote

import (
	"encoding/binary"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testSocket(t *testing.T) *websocket.Conn {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := up.Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer c.Close()
		for {
			if _, _, e = c.ReadMessage(); e != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func TestReplacementSingleTunnel(t *testing.T) {
	now := time.Now()
	cfg := MgrConfig{TunnelCap: 1, KeepaliveSeconds: 5, DrainSeconds: 180}
	m := &Mgr{config: cfg, isActivated: true, pending: make(map[*WSTunnel]*WSTunnel), draining: make(map[*WSTunnel]time.Time)}
	old := newTunnel(0, nil, &cfg)
	old.ws = testSocket(t)
	old.isActivated = true
	old.health = newTunnelHealth(now, cfg)
	old.health.lastPing = now
	next := newTunnel(0, nil, &cfg)
	next.mgr = m
	next.isActivated = true
	next.health = newTunnelHealth(now, cfg)
	next.health.lastPing = now
	m.tunnels = []*WSTunnel{old}
	m.pending[old] = next
	m.maintain(now)
	selected, err := m.allocateWSTunnel()
	if err != nil || selected != old {
		t.Fatal("old tunnel unavailable while replacement unready")
	}
	selected.users.Add(-1)
	// A request admitted before the swap must keep the old connection alive.
	old.users.Add(1)
	next.onConnected(testSocket(t))
	// No maintain tick, Ping or Pong occurs before admission switches.
	if len(next.health.pending) != 0 || len(next.health.samples) != 0 {
		t.Fatal("unexpected readiness probe")
	}
	selected, err = m.allocateWSTunnel()
	if err != nil || selected != next {
		t.Fatal("new requests did not switch")
	}
	selected.users.Add(-1)
	m.maintain(now)
	if !old.active() {
		t.Fatal("existing request interrupted during drain")
	}
	m.draining[old] = now
	m.maintain(now)
	if old.active() {
		t.Fatal("drain deadline did not stop old tunnel")
	}
	next.stop()
}
func TestRTTDetection(t *testing.T) {
	now := time.Now()
	h := newTunnelHealth(now.Add(-10*time.Minute), MgrConfig{})
	for i := 0; i < 60; i++ {
		h.samples = append(h.samples, rttSample{now.Add(-time.Duration(120+i*5) * time.Second), 50 * time.Millisecond})
	}
	for i := 0; i < 12; i++ {
		h.samples = append(h.samples, rttSample{now.Add(-time.Duration(i*5) * time.Second), 600 * time.Millisecond})
	}
	if h.reason(now, 0, true) != "" {
		t.Fatal("must wait for sustained degradation")
	}
	for i := 0; i < 12; i++ {
		h.samples = append(h.samples, rttSample{now.Add(time.Duration(65-i*5) * time.Second), 600 * time.Millisecond})
	}
	if h.reason(now.Add(65*time.Second), 0, true) == "" {
		t.Fatal("single tunnel historical degradation not detected")
	}
	h.slowSince = time.Time{}
	h.samples = nil
	for i := 0; i < 12; i++ {
		h.samples = append(h.samples, rttSample{now.Add(-time.Duration(i) * time.Second), 50 * time.Millisecond})
	}
	h.samples = append(h.samples, rttSample{now, 5 * time.Second})
	if h.reason(now, 50*time.Millisecond, true) != "" || !h.slowSince.IsZero() {
		t.Fatal("one spike triggered degradation")
	}
}
func TestPongValidationAndAge(t *testing.T) {
	now := time.Now()
	h := newTunnelHealth(now, MgrConfig{MaxAgeSeconds: 3600})
	if h.expires.Before(now.Add(3300*time.Second)) || h.expires.After(now.Add(time.Hour)) {
		t.Fatal("invalid age jitter")
	}
	p := make([]byte, 9)
	p[0] = 1
	binary.LittleEndian.PutUint64(p[1:], 7)
	if h.pong(p, now) {
		t.Fatal("unsolicited pong accepted")
	}
	h.pending[7] = now
	if !h.pong(p, now.Add(time.Millisecond)) || h.pong(p, now.Add(time.Second)) {
		t.Fatal("matching or duplicate pong handling failed")
	}
	if h.reason(now.Add(time.Hour), 0, false) != "maximum age" {
		t.Fatal("age trigger missing")
	}
}
