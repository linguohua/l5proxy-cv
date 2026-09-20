package localsocks5

import (
	"bufio"
	"fmt"
	"l5proxy_cv/meta"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type socks5conn struct {
	*net.TCPConn
}

func (hc socks5conn) ID() *stack.TransportEndpointID {
	return nil
}

type LocalConfig struct {
	Address   string
	UseBypass bool

	TransportHandler    meta.HTTPSocks5TransportHandler
	UDPTransportHandler meta.UDPTransportHandler
	BypassHandler       meta.Bypass
}

type Mgr struct {
	cfg LocalConfig

	listener *net.TCPListener
}

func NewMgr(cfg *LocalConfig) meta.Local {
	if cfg.UDPTransportHandler == nil && cfg.TransportHandler != nil {
		if u, ok := cfg.TransportHandler.(meta.UDPTransportHandler); ok {
			cfg.UDPTransportHandler = u
		}
	}

	mgr := &Mgr{
		cfg: *cfg,
	}

	return mgr
}

func (mgr *Mgr) Name() string {
	return "socks5mode"
}

func (mgr *Mgr) Startup() error {
	if mgr.listener != nil {
		return fmt.Errorf("localsocks5.Mgr already startup")
	}

	var err error
	addr, err := net.ResolveTCPAddr("tcp", mgr.cfg.Address)
	if err != nil {
		return fmt.Errorf("localsocks5.Mgr resolve tcp address error:%s", err)
	}

	mgr.listener, err = net.ListenTCP("tcp", addr)
	if err != nil {
		return fmt.Errorf("localsocks5.Mgr ListenTCP error:%s", err)
	}

	log.Infof("Socks5 server startup, address:%s", mgr.cfg.Address)
	go mgr.serveSocks5()

	return nil
}

func (mgr *Mgr) Shutdown() error {
	if mgr.listener == nil {
		return fmt.Errorf("localsocks5.Mgr isn't running")
	}

	err := mgr.listener.Close()
	if err != nil {
		log.Errorf("localsocks5.Mgr shutdown TCP server failed:%s", err)
	}

	log.Info("Socks5 server shutdown")
	return nil
}

func (mgr *Mgr) serveSocks5() {
	for {
		conn, err := mgr.listener.Accept()
		if err != nil {
			log.Errorf("localsocks5.Mgr serveSocks5 error:%s", err)
			return
		}

		go mgr.serveSocks5Conn(conn)
	}
}

func (mgr *Mgr) serveSocks5Conn(conn net.Conn) {
	var handled = false
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("serveSocks5Conn Recovered. Error:%s", r)
		}

		if !handled {
			conn.Close()
		}
	}()

	bufConn := bufio.NewReader(conn)

	// Read the version byte
	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		log.Errorf("localsocks5.Mgr failed to get socks5 version byte: %v", err)
		return
	}

	// Ensure we are compatible
	if version[0] != socks5Version {
		log.Errorf("localsocks5.Mgr Unsupported SOCKS version: %v", version)
		return
	}

	var err = authenticate(conn, bufConn)
	if err != nil {
		log.Errorf("localsocks5.Mgr auth failed: %v", err)
		return
	}

	r1, err := newRequest(bufConn, conn)
	if err != nil {
		log.Errorf("localsocks5.Mgr newRequest error: %v", err)
		return
	}

	err = mgr.handleSocks5Request(r1)
	if err != nil {
		log.Errorf("localsocks5.Mgr handleSocks5Request error: %v", err)
		return
	}

	handled = true
}

func (mgr *Mgr) handleSocks5Request(r *request) error {
	// switch on the command
	switch r.command {
	case connectCommand:
		return mgr.handleSocks5Connect(r)
	case bindCommand:
		return mgr.handleSocks5Bind(r)
	case associateCommand:
		return mgr.handleSocks5Associate(r)
	default:
		if err := replySocks5Client(r.conn, commandNotSupported, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("unsupported command: %v", r.command)
	}
}

// NOTE: if error occurs, conn of the 'req' object must be closed in outer
func (mgr *Mgr) handleSocks5Connect(req *request) error {
	var extraBytes []byte

	if req.bufreader != nil {
		buffered := req.bufreader.Buffered()
		if buffered > 0 {
			extraBytes = make([]byte, buffered)
			n, err := req.bufreader.Read(extraBytes)
			if err != nil {
				return err
			}

			if n != buffered {
				return fmt.Errorf("handleConnect drain bufreader failed:%s", err)
			}
		}
	}

	cfg := mgr.cfg
	targetInfo := &meta.HTTPSocksTargetInfo{
		Port:       req.destAddr.port,
		DomainName: req.destAddr.fqdn,
		ExtraBytes: extraBytes,
	}

	tcpConn, ok := req.conn.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("handleConnect socks5 conn isn't tcp conn")
	}

	tcpConn.SetKeepAlivePeriod(5 * time.Second)
	tcpConn.SetNoDelay(true)
	tcpConn.SetKeepAlive(true)

	local := tcpConn.LocalAddr().(*net.TCPAddr)
	bind := addrSpec{ip: local.IP, port: local.Port}
	if err := replySocks5Client(req.conn, successReply, &bind); err != nil {
		return fmt.Errorf("failed to send reply to socks5 client: %v", err)
	}

	socks5conn := socks5conn{
		TCPConn: tcpConn,
	}

	if cfg.UseBypass && cfg.BypassHandler != nil {
		bypass := cfg.BypassHandler
		if bypass.BypassAble(targetInfo.DomainName) {
			bypass.HandleHttpSocks5TCP(socks5conn, targetInfo)
			return nil
		}
	}

	cfg.TransportHandler.HandleHttpSocks5TCP(socks5conn, targetInfo)
	return nil
}

func (mgr *Mgr) handleSocks5Bind(req *request) error {
	// TODO: Support bind
	if err := replySocks5Client(req.conn, commandNotSupported, nil); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	return fmt.Errorf("unsupport socks5 Bind command")
}

func (mgr *Mgr) handleSocks5Associate(req *request) error {
	udpHandler := mgr.cfg.UDPTransportHandler
	if udpHandler == nil {
		if err := replySocks5Client(req.conn, commandNotSupported, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("unsupported socks5 Associate command: no UDPTransportHandler")
	}

	session, err := newUDPSession(mgr, req)
	if err != nil {
		_ = replySocks5Client(req.conn, serverFailure, nil)
		return fmt.Errorf("failed to create UDP session: %v", err)
	}
	defer session.close()

	// Reply with the relay UDP address
	bind := addrSpec{ip: session.bindIP, port: session.bindPort}
	if err := replySocks5Client(req.conn, successReply, &bind); err != nil {
		return fmt.Errorf("failed to send reply to socks5 client: %v", err)
	}

	// Serve UDP forwarding
	go session.serveUDP()

	// RFC 1928: A UDP association terminates when the TCP connection that the
	// UDP ASSOCIATE request arrived on terminates.
	buf := make([]byte, 1)
	for {
		_, err := req.conn.Read(buf)
		if err != nil {
			break
		}
	}

	return nil
}
