package localsocks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type udpSession struct {
	mgr       *Mgr
	req       *request
	listener  *net.UDPConn
	bindIP    net.IP
	bindPort  int
	closed    bool
	closeLock sync.Mutex

	vconnsMu sync.Mutex
	vconns   map[string]*socks5VirtualUDPConn
}

func newUDPSession(mgr *Mgr, req *request) (*udpSession, error) {
	var bindIP net.IP
	if tcpAddr, ok := req.conn.LocalAddr().(*net.TCPAddr); ok {
		bindIP = tcpAddr.IP
	}
	if bindIP == nil || bindIP.IsUnspecified() {
		bindIP = net.ParseIP("127.0.0.1")
	}

	udpAddr := &net.UDPAddr{IP: bindIP, Port: 0}
	listener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		udpAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
		listener, err = net.ListenUDP("udp", udpAddr)
		if err != nil {
			return nil, err
		}
	}

	lAddr := listener.LocalAddr().(*net.UDPAddr)

	return &udpSession{
		mgr:      mgr,
		req:      req,
		listener: listener,
		bindIP:   bindIP,
		bindPort: lAddr.Port,
		vconns:   make(map[string]*socks5VirtualUDPConn),
	}, nil
}

func (s *udpSession) close() {
	s.closeLock.Lock()
	if s.closed {
		s.closeLock.Unlock()
		return
	}
	s.closed = true
	s.closeLock.Unlock()

	_ = s.listener.Close()

	s.vconnsMu.Lock()
	vconns := s.vconns
	s.vconns = make(map[string]*socks5VirtualUDPConn)
	s.vconnsMu.Unlock()

	for _, vc := range vconns {
		vc.Close()
	}
}

func (s *udpSession) serveUDP() {
	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := s.listener.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if n < 4 {
			continue
		}

		// Validate SOCKS5 UDP Header: RSV(2) + FRAG(1)
		if buf[0] != 0 || buf[1] != 0 {
			continue
		}
		if buf[2] != 0 {
			// Fragmentation is not supported per RFC 1928, drop datagram
			continue
		}

		atyp := buf[3]
		var targetDomain string
		var dstIP net.IP
		var dstPort int
		var payloadOffset int

		switch atyp {
		case ipv4Address: // 0x01
			if n < 10 {
				continue
			}
			dstIP = make([]byte, net.IPv4len)
			copy(dstIP, buf[4:8])
			dstPort = int(binary.BigEndian.Uint16(buf[8:10]))
			payloadOffset = 10
		case fqdnAddress: // 0x03
			domainLen := int(buf[4])
			if n < 7+domainLen {
				continue
			}
			targetDomain = string(buf[5 : 5+domainLen])
			dstPort = int(binary.BigEndian.Uint16(buf[5+domainLen : 7+domainLen]))
			payloadOffset = 7 + domainLen
			dstIP = net.IPv4zero
		case ipv6Address: // 0x04
			if n < 22 {
				continue
			}
			dstIP = make([]byte, net.IPv6len)
			copy(dstIP, buf[4:20])
			dstPort = int(binary.BigEndian.Uint16(buf[20:22]))
			payloadOffset = 22
		default:
			continue
		}

		payload := buf[payloadOffset:n]

		key := s.vconnKey(clientAddr, targetDomain, dstIP, dstPort)
		s.vconnsMu.Lock()
		vconn, ok := s.vconns[key]
		if !ok {
			vconn = newSocks5VirtualUDPConn(clientAddr, dstIP, dstPort, targetDomain, s.listener, func() {
				s.removeVconn(key)
			})
			s.vconns[key] = vconn
			s.vconnsMu.Unlock()

			payloadCopy := make([]byte, len(payload))
			copy(payloadCopy, payload)

			go s.mgr.cfg.UDPTransportHandler.HandleUDP(vconn, payloadCopy)
		} else {
			s.vconnsMu.Unlock()
			payloadCopy := make([]byte, len(payload))
			copy(payloadCopy, payload)
			vconn.pushPacket(payloadCopy)
		}
	}
}

func (s *udpSession) vconnKey(client *net.UDPAddr, domain string, ip net.IP, port int) string {
	if len(domain) > 0 {
		return fmt.Sprintf("%s->%s:%d", client.String(), domain, port)
	}
	return fmt.Sprintf("%s->%s:%d", client.String(), ip.String(), port)
}

func (s *udpSession) removeVconn(key string) {
	s.vconnsMu.Lock()
	delete(s.vconns, key)
	s.vconnsMu.Unlock()
}

type socks5VirtualUDPConn struct {
	clientAddr   *net.UDPAddr
	dstIP        net.IP
	dstPort      int
	targetDomain string
	udpListener  *net.UDPConn
	onClose      func()

	packetCh  chan []byte
	closeCh   chan struct{}
	closeOnce sync.Once

	readDeadlineMu sync.Mutex
	readDeadline   time.Time
}

func newSocks5VirtualUDPConn(clientAddr *net.UDPAddr, dstIP net.IP, dstPort int, targetDomain string, listener *net.UDPConn, onClose func()) *socks5VirtualUDPConn {
	return &socks5VirtualUDPConn{
		clientAddr:   clientAddr,
		dstIP:        dstIP,
		dstPort:      dstPort,
		targetDomain: targetDomain,
		udpListener:  listener,
		onClose:      onClose,
		packetCh:     make(chan []byte, 128),
		closeCh:      make(chan struct{}),
	}
}

func (c *socks5VirtualUDPConn) pushPacket(data []byte) {
	select {
	case <-c.closeCh:
	case c.packetCh <- data:
	default:
		log.Debugf("socks5VirtualUDPConn queue full, dropping packet for %s", c.targetDomain)
	}
}

func (c *socks5VirtualUDPConn) ID() *stack.TransportEndpointID {
	var remoteIP net.IP = c.clientAddr.IP
	if ip4 := remoteIP.To4(); ip4 != nil {
		remoteIP = ip4
	}

	var localIP net.IP = c.dstIP
	if ip4 := localIP.To4(); ip4 != nil {
		localIP = ip4
	}

	return &stack.TransportEndpointID{
		RemotePort:    uint16(c.clientAddr.Port),
		RemoteAddress: tcpip.AddrFromSlice(remoteIP),
		LocalPort:     uint16(c.dstPort),
		LocalAddress:  tcpip.AddrFromSlice(localIP),
	}
}

func (c *socks5VirtualUDPConn) TargetDomain() string {
	return c.targetDomain
}

func (c *socks5VirtualUDPConn) Read(b []byte) (int, error) {
	c.readDeadlineMu.Lock()
	deadline := c.readDeadline
	c.readDeadlineMu.Unlock()

	var timeoutCh <-chan time.Time
	if !deadline.IsZero() {
		dur := time.Until(deadline)
		if dur <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(dur)
		defer timer.Stop()
		timeoutCh = timer.C
	}

	select {
	case <-c.closeCh:
		return 0, io.EOF
	case <-timeoutCh:
		return 0, os.ErrDeadlineExceeded
	case data, ok := <-c.packetCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, data)
		return n, nil
	}
}

func (c *socks5VirtualUDPConn) WriteTo(data []byte, _ net.Addr) (int, error) {
	var header []byte
	if len(c.targetDomain) > 0 {
		dBytes := []byte(c.targetDomain)
		header = make([]byte, 7+len(dBytes))
		header[0] = 0           // RSV
		header[1] = 0           // RSV
		header[2] = 0           // FRAG
		header[3] = fqdnAddress // 0x03
		header[4] = byte(len(dBytes))
		copy(header[5:], dBytes)
		binary.BigEndian.PutUint16(header[5+len(dBytes):], uint16(c.dstPort))
	} else if ip4 := c.dstIP.To4(); ip4 != nil {
		header = make([]byte, 10)
		header[0] = 0
		header[1] = 0
		header[2] = 0
		header[3] = ipv4Address // 0x01
		copy(header[4:8], ip4)
		binary.BigEndian.PutUint16(header[8:10], uint16(c.dstPort))
	} else {
		header = make([]byte, 22)
		header[0] = 0
		header[1] = 0
		header[2] = 0
		header[3] = ipv6Address // 0x04
		copy(header[4:20], c.dstIP.To16())
		binary.BigEndian.PutUint16(header[20:22], uint16(c.dstPort))
	}

	packet := make([]byte, len(header)+len(data))
	copy(packet, header)
	copy(packet[len(header):], data)

	_, err := c.udpListener.WriteToUDP(packet, c.clientAddr)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

func (c *socks5VirtualUDPConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCh)
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

func (c *socks5VirtualUDPConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.clientAddr)
}

func (c *socks5VirtualUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.clientAddr, err
}

func (c *socks5VirtualUDPConn) LocalAddr() net.Addr {
	return c.udpListener.LocalAddr()
}

func (c *socks5VirtualUDPConn) RemoteAddr() net.Addr {
	return c.clientAddr
}

func (c *socks5VirtualUDPConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

func (c *socks5VirtualUDPConn) SetReadDeadline(t time.Time) error {
	c.readDeadlineMu.Lock()
	c.readDeadline = t
	c.readDeadlineMu.Unlock()
	return nil
}

func (c *socks5VirtualUDPConn) SetWriteDeadline(t time.Time) error { return nil }
