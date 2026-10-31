package remote

import (
	"fmt"
	"l5proxy_cv/meta"
	"net"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

type UdpStub struct {
	tnl         *WSTunnel
	conn        meta.UDPConn
	lastActvity atomic.Int64
}

func newUdpStub(tnl *WSTunnel, conn meta.UDPConn) *UdpStub {
	ustub := &UdpStub{tnl: tnl, conn: conn}
	ustub.lastActvity.Store(time.Now().UnixNano())
	return ustub
}

func (u *UdpStub) srcAddress() *UDPAddr {
	conn := u.conn
	ip := conn.ID().RemoteAddress.AsSlice()
	if ip4 := net.IP(ip).To4(); ip4 != nil {
		ip = ip4
	}
	return &UDPAddr{Port: int(conn.ID().RemotePort), IP: ip}
}

func (u *UdpStub) dstAddress() *UDPAddr {
	conn := u.conn
	domain := conn.TargetDomain()
	if len(domain) > 0 {
		return &UDPAddr{Port: int(conn.ID().LocalPort), Domain: domain}
	}
	ip := conn.ID().LocalAddress.AsSlice()
	if ip4 := net.IP(ip).To4(); ip4 != nil {
		ip = ip4
	}
	return &UDPAddr{Port: int(conn.ID().LocalPort), IP: ip}
}

func (u *UdpStub) writeTo(data []byte, addr net.Addr) error {
	conn := u.conn
	if conn == nil {
		return fmt.Errorf("write udp conn == nil")
	}

	u.touch()

	wrote := 0
	l := len(data)
	for {
		n, err := conn.WriteTo(data[wrote:], addr)
		if err != nil {
			return err
		}

		wrote = wrote + n
		if wrote == l {
			break
		}
	}

	return nil
}

func (u *UdpStub) onUDPMessage(data []byte) {
	u.touch()
	u.tnl.onClientUDPData(data, u.srcAddress(), u.dstAddress())
}

func (u *UdpStub) proxy(extra []byte) {
	conn := u.conn
	if conn == nil {
		log.Error("conn == nil")
		return
	}

	u.onUDPMessage(extra)

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Debugf("Read error %s, UDPConn %s %s was close", err.Error(), u.srcAddress().String(), u.dstAddress().String())
			break
		}

		if n == 0 {
			log.Debug("UDP read n==0")
			break
		}

		u.onUDPMessage(buf[:n])

	}
}

func (u *UdpStub) close() {
	u.conn.Close()
}

func (u *UdpStub) touch() {
	u.lastActvity.Store(time.Now().UnixNano())
	if u.tnl.idleTimeout > 0 {
		u.conn.SetReadDeadline(time.Now().Add(u.tnl.idleTimeout))
	}
}
