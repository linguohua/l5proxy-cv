package remote

import (
	"encoding/binary"
	log "github.com/sirupsen/logrus"
	"math/rand"
	"time"
)

type tunnelHealth struct {
	expires, lastPing time.Time
	pending           map[uint64]time.Time
}

func newTunnelHealth(now time.Time, cfg MgrConfig) tunnelHealth {
	h := tunnelHealth{lastPing: now, pending: make(map[uint64]time.Time)}
	if cfg.MaxAgeSeconds > 0 {
		age := time.Duration(cfg.MaxAgeSeconds) * time.Second
		jitter := age / 12
		if jitter > 300*time.Second {
			jitter = 300 * time.Second
		}
		h.expires = now.Add(age - time.Duration(rand.Int63n(int64(jitter)+1)))
	}
	return h
}
func (h *tunnelHealth) pong(data []byte, now time.Time) bool {
	if len(data) < 9 || data[0] == 0 || len(data) != 9+2*(int(data[0])-1) {
		return false
	}
	token := binary.LittleEndian.Uint64(data[len(data)-8:])
	_, ok := h.pending[token]
	if !ok {
		return false
	}
	delete(h.pending, token)

	return true
}
func (h *tunnelHealth) reason(now time.Time) string {
	if !h.expires.IsZero() && !now.Before(h.expires) {
		return "maximum age"
	}
	return ""
}
func (t *WSTunnel) mgrConfig() MgrConfig {
	if t.mgr != nil {
		return t.mgr.config
	}
	return MgrConfig{}
}
func (t *WSTunnel) active() bool { t.wsLock.Lock(); defer t.wsLock.Unlock(); return t.isActivated }
func (t *WSTunnel) available() bool {
	t.wsLock.Lock()
	defer t.wsLock.Unlock()
	return t.isValid() && !t.draining
}
func (t *WSTunnel) tick(now time.Time, interval time.Duration) {
	t.keepaliveIfIdle(now, interval)
	t.cache.keepalive()
}
func (t *WSTunnel) empty() bool {
	if t.users.Load() != 0 {
		return false
	}
	t.reqq.l.Lock()
	defer t.reqq.l.Unlock()
	for _, r := range t.reqq.array {
		if r.isUsed {
			return false
		}
	}
	empty := true
	t.cache.ustubs.Range(func(_, _ any) bool { empty = false; return false })
	return empty
}

// maintain serializes admission and replacement. A pending connection never
// removes its predecessor from the admission pool until its WebSocket connection is established.
func (m *Mgr) maintain(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.isActivated {
		return
	}
	interval := time.Duration(m.config.KeepaliveSeconds) * time.Second
	for _, t := range m.tunnels {
		t.tick(now, interval)
	}
	for _, t := range m.pending {
		t.tick(now, interval)
	}
	for t, deadline := range m.draining {
		t.tick(now, interval)
		if t.empty() || !now.Before(deadline) {
			t.stop()
			delete(m.draining, t)
			log.Infof("tunnel %d drain finished", t.id)
		}
	}
	for _, old := range m.tunnels {
		next := m.pending[old]
		if next != nil {
			continue
		}
		// Bound overlap to one predecessor per slot, including very short configured ages.
		draining := false
		for t := range m.draining {
			if t.id == old.id {
				draining = true
			}
		}
		if draining {
			continue
		}
		old.wsLock.Lock()
		reason := ""
		if old.isValid() {
			reason = old.health.reason(now)
		}
		old.wsLock.Unlock()
		if reason == "" {
			continue
		}
		next = newTunnel(old.id, m.dnsResolver, &m.config)
		next.mgr = m
		next.protector = m.config.Protector
		m.pending[old] = next
		log.Infof("tunnel %d starting replacement: %s", old.id, reason)
		next.start()
	}
}

// connected promotes a replacement immediately after the WebSocket handshake.
// No probe or Pong is required. Lock order matches admission and maintenance.
func (m *Mgr) connected(next *WSTunnel) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.isActivated {
		return
	}
	next.wsLock.Lock()
	defer next.wsLock.Unlock()
	if !next.isValid() {
		return
	}
	for i, old := range m.tunnels {
		if m.pending[old] != next {
			continue
		}
		old.wsLock.Lock()
		old.draining = true
		old.wsLock.Unlock()
		m.tunnels[i] = next
		m.draining[old] = time.Now().Add(time.Duration(m.config.DrainSeconds) * time.Second)
		delete(m.pending, old)
		log.Infof("tunnel %d replacement connected; old connection draining", old.id)
		return
	}
}
