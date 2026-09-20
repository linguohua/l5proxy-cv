package meta

import (
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TCPConn implements the net.Conn interface.
type TCPConn interface {
	net.Conn

	// ID returns the transport endpoint id of TCPConn.
	ID() *stack.TransportEndpointID
	CloseWrite() error
	CloseRead() error
}

// UDPConn implements net.Conn and net.PacketConn.
type UDPConn interface {
	net.Conn
	net.PacketConn

	// ID returns the transport endpoint id of UDPConn.
	ID() *stack.TransportEndpointID
	TargetDomain() string
}

// UDPTransportHandler is a UDP connection handler that implements HandleUDP method.
type UDPTransportHandler interface {
	HandleUDP(UDPConn, []byte)
}

// TunTransportHandler is a TCP/UDP connection handler that implements
// HandleTCP and HandleUDP methods.
type TunTransportHandler interface {
	HandleTCP(TCPConn)
	UDPTransportHandler

	OnStackReady(LocalGivsorNetwork)
}

// LocalGivsorNetwork is for creating connections
type LocalGivsorNetwork interface {
	NewTCP4(id *stack.TransportEndpointID) (TCPConn, error)
	NewUDP4(id *stack.TransportEndpointID) (UDPConn, error)
}

type HTTPSocksTargetInfo struct {
	DomainName string
	Port       int

	ExtraBytes []byte
}

type HTTPSocks5TransportHandler interface {
	HandleHttpSocks5TCP(TCPConn, *HTTPSocksTargetInfo)
}

type Local interface {
	Startup() error
	Shutdown() error
	Name() string
}

type Bypass interface {
	HTTPSocks5TransportHandler
	BypassAble(ipOrDomainName string) bool
	BypassAbleDomain(domainName string) bool
}
