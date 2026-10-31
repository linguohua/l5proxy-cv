package remote

import (
	"encoding/binary"
	log "github.com/sirupsen/logrus"
	"math/rand"
	"sort"
	"time"
)

type rttSample struct {
	at  time.Time
	rtt time.Duration
}
type tunnelHealth struct {
	connected, expires, slowSince, lastPing time.Time
	pending                                 map[uint64]time.Time
	samples                                 []rttSample
}

func newTunnelHealth(now time.Time, cfg MgrConfig) tunnelHealth {
	h := tunnelHealth{connected: now, pending: make(map[uint64]time.Time)}
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
	sent, ok := h.pending[token]
	if !ok {
		return false
	}
	delete(h.pending, token)
	h.samples = append(h.samples, rttSample{now, now.Sub(sent)})
	i := 0
	for i < len(h.samples) && now.Sub(h.samples[i].at) > 11*time.Minute {
		i++
	}
	h.samples = h.samples[i:]
	return true
}
func median(v []time.Duration) time.Duration {
	if len(v) == 0 {
		return 0
	}
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v[len(v)/2]
}
func (h *tunnelHealth) current(now time.Time) time.Duration {
	var v []time.Duration
	for _, s := range h.samples {
		if now.Sub(s.at) <= time.Minute {
			v = append(v, s.rtt)
		}
	}
	if len(v) < 3 {
		return 0
	}
	return median(v)
}
func (h *tunnelHealth) reason(now time.Time, peer time.Duration, enabled bool) string {
	if !h.expires.IsZero() && !now.Before(h.expires) {
		return "maximum age"
	}
	if !enabled || now.Sub(h.connected) < 2*time.Minute {
		return ""
	}
	current := h.current(now)
	var history []time.Duration
	for _, s := range h.samples {
		age := now.Sub(s.at)
		if age > time.Minute && age <= 11*time.Minute {
			history = append(history, s.rtt)
		}
	}
	baseline := median(history)
	slow := current > 0 && ((peer > 0 && current > 3*peer && current-peer > 200*time.Millisecond) || (len(history) >= 6 && baseline > 0 && current > 3*baseline && current-baseline > 300*time.Millisecond))
	if !slow {
		h.slowSince = time.Time{}
		return ""
	}
	if h.slowSince.IsZero() {
		h.slowSince = now
	}
	if now.Sub(h.slowSince) >= time.Minute {
		return "sustained RTT degradation"
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
	t.wsLock.Lock()
	due := t.ws != nil && now.Sub(t.health.lastPing) >= interval
	if due {
		t.health.lastPing = now
	}
	t.wsLock.Unlock()
	if due {
		t.keepalive()
	}
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
		var peers []time.Duration
		for _, other := range m.tunnels {
			if other == old {
				continue
			}
			other.wsLock.Lock()
			if other.isValid() {
				v := other.health.current(now)
				if v > 0 {
					peers = append(peers, v)
				}
			}
			other.wsLock.Unlock()
		}
		old.wsLock.Lock()
		reason := ""
		if old.isValid() {
			reason = old.health.reason(now, median(peers), m.config.RTTRebuild)
		}
		old.wsLock.Unlock()
		if reason == "" {
			continue
		}
		if reason == "sustained RTT degradation" && now.Sub(m.lastRebuild) < 5*time.Minute {
			continue
		}
		next = newTunnel(old.id, m.dnsResolver, &m.config)
		next.mgr = m
		next.protector = m.config.Protector
		m.pending[old] = next
		if reason == "sustained RTT degradation" {
			m.lastRebuild = now
		}
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
