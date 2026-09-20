package localtun

// base on:
// https://github.com/xjasonlyu/tun2socks/blob/main/core/udp.go
import (
	"l5proxy_cv/meta"

	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func withUDPHandler(handle func(meta.UDPConn, []byte)) Option {
	return func(s *stack.Stack) error {
		udpForwarder := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
			var (
				wq waiter.Queue
				id = r.ID()
			)
			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				log.Errorf("forward udp request failed: %s:%d->%s:%d: %s",
					id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort, err)
				return
			}

			log.Debugf("forward udp request: %s:%d->%s:%d",
				id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort)

			conn := &udpConn{
				UDPConn: gonet.NewUDPConn(&wq, ep),
				id:      id,
			}
			handle(conn, nil)
		})
		s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
		return nil
	}
}

type udpConn struct {
	*gonet.UDPConn
	id stack.TransportEndpointID
}

func (c *udpConn) ID() *stack.TransportEndpointID {
	return &c.id
}

func (c *udpConn) TargetDomain() string {
	return ""
}
