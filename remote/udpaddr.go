package remote

import (
	"encoding/binary"
	"fmt"
	"net"
)

type UDPAddr struct {
	Port   int
	IP     net.IP
	Domain string
}

func (a *UDPAddr) String() string {
	if a == nil {
		return "<nil>"
	}
	if len(a.Domain) > 0 {
		return fmt.Sprintf("%s:%d", a.Domain, a.Port)
	}
	return (&net.UDPAddr{IP: a.IP, Port: a.Port}).String()
}

func (a *UDPAddr) ToNetUDPAddr() *net.UDPAddr {
	if a == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   a.IP,
		Port: a.Port,
	}
}

// WriteAddress encodes the address according to Scheme A:
// - Domain: Port(2 bytes LE) + ipType(0x01) + domainLen(1 byte) + domainName(bytes)
// - IPv4:   Port(2 bytes LE) + ipType(0x00) + IP(4 bytes)
// - IPv6:   Port(2 bytes LE) + ipType(0x02) + IP(16 bytes)
func (a *UDPAddr) WriteAddress() []byte {
	if len(a.Domain) > 0 {
		domainBytes := []byte(a.Domain)
		domainLen := len(domainBytes)
		if domainLen > 255 {
			domainBytes = domainBytes[:255]
			domainLen = 255
		}
		buf := make([]byte, 4+domainLen)
		binary.LittleEndian.PutUint16(buf[0:], uint16(a.Port))
		buf[2] = 1 // domain type
		buf[3] = byte(domainLen)
		copy(buf[4:], domainBytes)
		return buf
	}

	ip := a.IP
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	buf := make([]byte, 3+len(ip))
	binary.LittleEndian.PutUint16(buf[0:], uint16(a.Port))
	if len(ip) > net.IPv4len {
		buf[2] = 2 // ipv6
	} else {
		buf[2] = 0 // ipv4
	}
	copy(buf[3:], ip)
	return buf
}

// ParseUDPAddr parses an encoded UDP address:
// - IPv4:   Port(2 LE) + ipType(0) + IPv4(4)      => 7 bytes
// - Domain: Port(2 LE) + ipType(1) + len(1) + name => 4 + len bytes
// - IPv6:   Port(2 LE) + ipType(2) + IPv6(16)     => 19 bytes
func ParseUDPAddr(msg []byte) (*UDPAddr, int, error) {
	if len(msg) < 3 {
		return nil, 0, fmt.Errorf("message too short for UDP address")
	}

	port := binary.LittleEndian.Uint16(msg[0:])
	ipType := msg[2]

	switch ipType {
	case 0:
		if len(msg) < 7 {
			return nil, 0, fmt.Errorf("message too short for IPv4 UDP address")
		}
		ip := make([]byte, net.IPv4len)
		copy(ip, msg[3:7])
		return &UDPAddr{Port: int(port), IP: ip}, 7, nil
	case 1:
		if len(msg) < 4 {
			return nil, 0, fmt.Errorf("message too short for domain length")
		}
		domainLen := int(msg[3])
		if len(msg) < 4+domainLen {
			return nil, 0, fmt.Errorf("message too short for domain name")
		}
		domain := string(msg[4 : 4+domainLen])
		return &UDPAddr{Port: int(port), Domain: domain}, 4 + domainLen, nil
	case 2:
		if len(msg) < 19 {
			return nil, 0, fmt.Errorf("message too short for IPv6 UDP address")
		}
		ip := make([]byte, net.IPv6len)
		copy(ip, msg[3:19])
		return &UDPAddr{Port: int(port), IP: ip}, 19, nil
	default:
		return nil, 0, fmt.Errorf("unsupported UDP address ipType: %d", ipType)
	}
}
