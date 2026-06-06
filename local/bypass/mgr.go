package localbypass

import (
	"fmt"
	"l5proxy_cv/meta"
	"l5proxy_cv/mydns"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type LocalConfig struct {
	WhitelistURL  string
	BlacklistFile string

	Protector func(fd uint64)

	AliDNS string

	All bool
}

type bypassconn struct {
	*net.TCPConn
}

func (bp bypassconn) ID() *stack.TransportEndpointID {
	return nil
}

type Mgr struct {
	cfg LocalConfig

	isActivated bool

	whitelistLock sync.Mutex
	whitelist     map[string]struct{}

	blacklistLock sync.Mutex
	blacklist     map[string]struct{}
}

func NewMgr(cfg *LocalConfig) meta.Local {
	mgr := &Mgr{
		cfg: *cfg,

		whitelist: make(map[string]struct{}),
		blacklist: make(map[string]struct{}),
	}

	return mgr
}

func (mgr *Mgr) Name() string {
	return "bypassmode"
}

func (mgr *Mgr) Startup() error {
	if mgr.isActivated {
		return fmt.Errorf("bypass mode already startup")
	}

	if !mgr.cfg.All {
		go mgr.loadWhitelist()
	}

	mgr.loadBlacklist()

	mgr.isActivated = true

	log.Info("bypass mode startup")
	return nil
}

func (mgr *Mgr) Shutdown() error {
	if !mgr.isActivated {
		return fmt.Errorf("bypass mode is not runnning")
	}

	mgr.isActivated = false
	log.Info("bypass mode shutdown")
	return nil
}

func (mgr *Mgr) HandleHttpSocks5TCP(conn meta.TCPConn, targetInfo *meta.HTTPSocksTargetInfo) {
	defer conn.Close()

	var addr string
	var id = conn.ID()
	if targetInfo != nil {
		addr = fmt.Sprintf("%s:%d", targetInfo.DomainName, targetInfo.Port)
	} else if id != nil {
		// use conn remote address
		addr = fmt.Sprintf("%s:%d", id.LocalAddress.String(), id.LocalPort)
	} else {
		log.Errorf("localbypass.Mgr handle tcp failed, no target address found")
		return
	}

	conn2, err := mydns.DialWithProtector(nil, mgr.cfg.Protector, nil, "tcp", addr)
	if err != nil {
		log.Errorf("localbypass.Mgr dial %s failed:%s", addr, err)
		return
	}

	defer conn2.Close()

	if targetInfo != nil && len(targetInfo.ExtraBytes) > 0 {
		n, err := conn2.Write(targetInfo.ExtraBytes)
		if err != nil {
			log.Errorf("localbypass.Mgr write extra bytes to %s failed:%s", addr, err)
			return
		}

		if n != len(targetInfo.ExtraBytes) {
			log.Errorf("localbypass.Mgr write extra bytes to %s failed, expected %d, actual %d",
				addr, len(targetInfo.ExtraBytes), n)
			return
		}
	}

	conn3, ok := conn2.(*net.TCPConn)
	if !ok {
		log.Error("localbypass.Mgr convert conn to TCPConn failed")
		return
	}

	wg := &sync.WaitGroup{}
	wg.Add(2)

	bc := bypassconn{
		TCPConn: conn3,
	}

	go mgr.pipeTcpSocket(conn, bc, wg)
	go mgr.pipeTcpSocket(bc, conn, wg)

	log.Infof("proxy[bypass/tcp] to %s", addr)
	wg.Wait()
}

func (mgr *Mgr) pipeTcpSocket(from meta.TCPConn, to meta.TCPConn, wg *sync.WaitGroup) {
	buf := make([]byte, 16*1024) // 16K
	for {
		n, err := from.Read(buf)

		if err != nil {
			// log.Println("proxy read failed:", err)
			to.Close()
			break
		}

		if n == 0 {
			// log.Println("proxy read, server half close")
			to.CloseWrite()
			break
		}

		to.SetWriteDeadline(time.Now().Add(10 * time.Second))
		n1, err := to.Write(buf[0:n])
		if n1 != n {
			to.Close()
			break
		}

		if err != nil {
			to.Close()
			break
		}
	}

	wg.Done()
}

func (mgr *Mgr) BypassAble(ipOrDomainName string) bool {
	if !mgr.isActivated {
		return false
	}

	// Blacklist takes priority — hosts in blacklist must go through remote proxy
	if mgr.isDomainInBlacklist(ipOrDomainName) {
		return false
	}

	if mgr.cfg.All {
		return true
	}

	if mgr.isLocalIP(ipOrDomainName) {
		return true
	}

	if mgr.isDomainInWhitelist(ipOrDomainName) {
		return true
	}

	return false
}

func (mgr *Mgr) BypassAbleDomain(domainName string) bool {
	// Blacklist takes priority — hosts in blacklist must go through remote proxy
	if mgr.isDomainInBlacklist(domainName) {
		return false
	}
	return mgr.isDomainInWhitelist(domainName)
}

func (mgr *Mgr) isLocalIP(ip string) bool {
	// TODO: ipv6
	return isStringLocalIP4(ip)
}

func (mgr *Mgr) isDomainInWhitelist(domainName string) bool {
	mgr.whitelistLock.Lock()
	defer mgr.whitelistLock.Unlock()

	return isDomainIn(domainName, mgr.whitelist)
}

func (mgr *Mgr) isDomainInBlacklist(domainName string) bool {
	mgr.blacklistLock.Lock()
	defer mgr.blacklistLock.Unlock()

	return isDomainIn(domainName, mgr.blacklist)
}

func (mgr *Mgr) loadBlacklist() {
	if mgr.cfg.BlacklistFile == "" {
		return
	}

	m, err := loadBlacklistFile(mgr.cfg.BlacklistFile)
	if err != nil {
		log.Errorf("localbypass load blacklist file %s failed: %s", mgr.cfg.BlacklistFile, err)
		return
	}

	mgr.blacklistLock.Lock()
	mgr.blacklist = m
	mgr.blacklistLock.Unlock()

	log.Infof("localbypass.Mgr load blacklist host count: %d", len(m))
}

var (
	_ meta.Bypass = &Mgr{}
)
