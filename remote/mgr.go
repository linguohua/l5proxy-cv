package remote

import (
	"fmt"
	"l5proxy_cv/meta"
	"l5proxy_cv/mydns"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

type IMgr interface {
	meta.HTTPSocks5TransportHandler
	meta.TunTransportHandler
	Startup() error
	Shutdown() error
}

type MgrConfig struct {
	IsDummy      bool
	AliDNS       string
	WebsocketURL string
	TunnelCount  int
	TunnelCap    int

	MaxAgeSeconds      int
	DrainSeconds       int
	RTTRebuild         bool
	IdleTimeoutSeconds int
	KeepaliveSeconds   int
	KeepaliveLog       bool

	Protector func(fd uint64)
}

type Mgr struct {
	mu          sync.Mutex
	pending     map[*WSTunnel]*WSTunnel
	draining    map[*WSTunnel]time.Time
	done        chan struct{}
	lastRebuild time.Time
	config      MgrConfig
	index       atomic.Uint64
	tunnels     []*WSTunnel

	isActivated bool

	localGvisor meta.LocalGivsorNetwork

	dnsResolver *mydns.AlibbResolver0
}

func NewMgr(config *MgrConfig) IMgr {
	cfg := *config
	if cfg.KeepaliveSeconds <= 0 {
		cfg.KeepaliveSeconds = 5
	}
	if cfg.IsDummy {
		return &DummyMgr{
			config: cfg,
		}
	}

	if len(cfg.WebsocketURL) == 0 {
		cfg.WebsocketURL = "ws://127.0.0.1:8080/ws"
	}

	if cfg.TunnelCount < 1 {
		cfg.TunnelCount = 1
	}

	if cfg.TunnelCap < 1 {
		cfg.TunnelCap = 100
	}

	var host string
	url, err := url.Parse(cfg.WebsocketURL)
	if err != nil {
		log.Errorf("NewMgr parse URL failed:%s", err)
		host = "127.0.0.1"
	} else {
		host = url.Host
	}

	mgr := &Mgr{
		config:      cfg,
		dnsResolver: mydns.NewAlibbResolver(cfg.AliDNS, host, config.Protector),
	}

	return mgr
}

func (mgr *Mgr) OnStackReady(localGvisor meta.LocalGivsorNetwork) {
	mgr.localGvisor = localGvisor
}

func (mgr *Mgr) Startup() error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	log.Info("remote.Mgr.Startup called")

	if mgr.isActivated {
		return fmt.Errorf("remote.Mgr already startup")
	}

	mgr.pending = make(map[*WSTunnel]*WSTunnel)
	mgr.draining = make(map[*WSTunnel]time.Time)
	mgr.done = make(chan struct{})
	config := &mgr.config

	mgr.tunnels = make([]*WSTunnel, 0, config.TunnelCount)
	for i := 0; i < config.TunnelCount; i++ {
		tnl := newTunnel(i, mgr.dnsResolver, config)
		if config.Protector != nil {
			tnl.protector = config.Protector
		}

		tnl.mgr = mgr
		mgr.tunnels = append(mgr.tunnels, tnl)

		tnl.start()
	}

	mgr.isActivated = true

	go mgr.keepalive()

	log.Info("remote.Mgr.Startup completed")
	return nil
}

func (mgr *Mgr) Shutdown() error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if !mgr.isActivated {
		return fmt.Errorf("manager not started")
	}
	mgr.isActivated = false
	close(mgr.done)
	for _, t := range mgr.tunnels {
		t.stop()
	}
	for _, t := range mgr.pending {
		t.stop()
	}
	for t := range mgr.draining {
		t.stop()
	}
	return nil
}

func (mgr *Mgr) keepalive() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-mgr.done:
			return
		case now := <-ticker.C:
			mgr.maintain(now)
		}
	}
}

func (mgr *Mgr) HandleTCP(conn meta.TCPConn) {
	defer conn.Close()

	// allocate a usable tunnel
	tunnel, err := mgr.allocateWSTunnel()
	if err != nil {
		log.Errorf("mgr.allocateWSTunnel failed: %v", err)
		return
	}

	defer tunnel.users.Add(-1)

	log.Infof("proxy[tun/tcp] to %s", conn.ID().LocalAddress.String())

	err = tunnel.acceptTCPConn(conn)
	if err != nil {
		log.Errorf("tunnel.acceptTCPConn failed: %v", err)
		return
	}

}

func (mgr *Mgr) HandleHttpSocks5TCP(conn meta.TCPConn, target *meta.HTTPSocksTargetInfo) {
	defer conn.Close()

	// allocate a usable tunnel
	tunnel, err := mgr.allocateWSTunnel()
	if err != nil {
		log.Errorf("mgr.allocateWSTunnel failed: %v", err)
		return
	}

	defer tunnel.users.Add(-1)

	log.Infof("proxy[http-socks5/tcp] to %s:%d", target.DomainName, target.Port)

	err = tunnel.acceptHttpSocks5TCPConn(conn, target)
	if err != nil {
		log.Errorf("tunnel.acceptTCPConn failed: %v", err)
		return
	}
}

func (mgr *Mgr) HandleUDP(conn meta.UDPConn, extra []byte) {
	defer conn.Close()

	// allocate a usable tunnel
	tunnel, err := mgr.allocateWSTunnel()
	if err != nil {
		log.Errorf("mgr.allocateWSTunnel failed: %v", err)
		return
	}

	defer tunnel.users.Add(-1)

	log.Infof("proxy[tun/udp] to %s", conn.ID().LocalAddress.String())

	err = tunnel.acceptUDPConn(conn, extra)
	if err != nil {
		log.Errorf("tunnel.acceptUDPConn failed: %v", err)
		return
	}
}

func (mgr *Mgr) nextAllocIndex() uint64 {
	if len(mgr.tunnels) < 1 {
		return 0
	}

	return mgr.index.Add(1) % uint64(len(mgr.tunnels))
}

func (mgr *Mgr) allocateWSTunnel() (*WSTunnel, error) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if !mgr.isActivated {
		return nil, fmt.Errorf("manager stopped")
	}
	if len(mgr.tunnels) < 1 {
		return nil, fmt.Errorf("tunnels array is empty")
	}

	index := mgr.nextAllocIndex()
	firstIndex := index

	for {
		tnl := mgr.tunnels[index]
		if tnl.available() {
			tnl.users.Add(1)
			return tnl, nil
		}

		index = mgr.nextAllocIndex()
		if firstIndex == index {
			break
		}
	}

	return nil, fmt.Errorf("failed to find a valid tunnel")
}
