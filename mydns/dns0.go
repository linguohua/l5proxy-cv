package mydns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	mkdns "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

const (
	defaultDialTimeout = 5 * time.Second
)

type AlibbResolver0 struct {
	host      string
	protector func(fd uint64)

	locker     sync.Mutex
	isResolved bool
	ip         net.IP

	aliDNS string
}

func NewAlibbResolver(aliDNS1, host string, protector func(fd uint64)) *AlibbResolver0 {
	return &AlibbResolver0{
		host:       host,
		protector:  protector,
		isResolved: false,
		aliDNS:     aliDNS1,
	}
}

func (r *AlibbResolver0) GetHostIP(host string) (net.IP, error) {
	if host != r.host {
		return nil, fmt.Errorf("host not match, expected:%s, input:%s", r.host, host)
	}

	r.locker.Lock()
	defer r.locker.Unlock()

	if r.isResolved {
		return r.ip, nil
	}

	var ip net.IP
	var err error
	ip = net.ParseIP(r.host)
	if ip == nil {
		// not IP form, need DNS query
		ip, err = resolveHost4(r.aliDNS, r.host, r.protector)
		if err != nil {
			return nil, err
		}
	}

	log.Infof("AlibbResolver0, host:%s, ip:%s", host, ip.String())
	r.ip = ip
	r.isResolved = true
	return ip, nil
}

func AlibbDNSQuery(aliDNS1 string, data []byte, protector func(fd uint64)) ([]byte, error) {
	var d *net.Dialer
	if protector != nil {
		d = &net.Dialer{
			Control: func(network, address string, c syscall.RawConn) error {
				c.Control(func(fd uintptr) {
					protector(uint64(fd))
				})
				return nil
			},
		}
	} else {
		d = &net.Dialer{}
	}

	udpConn, err := d.Dial("udp", aliDNS1)
	if err != nil {
		return nil, err
	}

	defer udpConn.Close()
	n, err := udpConn.Write(data)
	if err != nil {
		return nil, err
	}

	if n != len(data) {
		return nil, fmt.Errorf("udp send to dns server length not match:%d != %d", n, len(data))
	}

	// read reply from DNS server
	buf := make([]byte, 600) // 600 is enough for DNS query reply
	udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err = udpConn.Read(buf)
	if err != nil {
		return nil, err
	}

	buf = buf[:n]
	return buf, nil
}

func resolveHost4(dnsServer, host string, protector func(fd uint64)) (net.IP, error) {
	msg := new(mkdns.Msg)
	msg.Id = mkdns.Id()
	msg.RecursionDesired = true
	msg.SetQuestion(mkdns.Fqdn(host), mkdns.TypeA)
	packed, err := msg.Pack() // generate a DNS query packet
	if err != nil {
		return nil, err
	}

	buf, err := AlibbDNSQuery(dnsServer, packed, protector)
	if err != nil {
		return nil, err
	}

	resp := new(mkdns.Msg)
	err = resp.Unpack(buf)
	if err != nil {
		return nil, err
	}

	if resp.Id != msg.Id {
		return nil, fmt.Errorf("DNS reply ID mismatch")
	}

	for _, answer := range resp.Answer {
		t, ok := answer.(*mkdns.A)
		if ok {
			return t.A, nil
		}
	}

	return nil, fmt.Errorf("no A record found in DNS reply")
}

func DialWithProtector(dnsResolver *AlibbResolver0, protector func(uint64),
	ctx context.Context, network, addr string) (net.Conn, error) {

	var addr2 string
	if dnsResolver != nil {
		var hostString, portString string
		if h, p, err := net.SplitHostPort(addr); err == nil {
			hostString = h
			portString = p
		} else {
			hostString = addr
			portString = ""
		}

		ip, err := dnsResolver.GetHostIP(hostString)
		if err != nil {
			return nil, err
		}

		if len(portString) > 0 {
			addr2 = net.JoinHostPort(ip.String(), portString)
		} else {
			addr2 = ip.String()
		}
	} else {
		addr2 = addr
	}

	var d2 *net.Dialer
	if protector != nil {
		d2 = &net.Dialer{
			Timeout: defaultDialTimeout,
			Control: func(network, address string, c syscall.RawConn) error {
				c.Control(func(fd uintptr) {
					protector(uint64(fd))
				})
				return nil
			},
		}
	} else {
		d2 = &net.Dialer{
			Timeout: defaultDialTimeout,
		}
	}

	if ctx != nil {
		return d2.DialContext(ctx, network, addr2)
	} else {
		return d2.Dial(network, addr2)
	}
}
