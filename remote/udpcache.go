package remote

import (
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	udpTimeOut            = 120 * time.Second
	udpCacheKeepaliveTime = 30 * time.Second
)

type UdpCache struct {
	// key=hash(src+dst)
	ustubs        sync.Map
	lastKeepalive time.Time
}

func newUdpCache() *UdpCache {
	return &UdpCache{
		lastKeepalive: time.Now(),
	}
}

func (c *UdpCache) add(ustub *UdpStub) {
	key := c.key(ustub.srcAddress(), ustub.dstAddress())
	c.ustubs.Store(key, ustub)
}

func (c *UdpCache) get(src, dst *UDPAddr) *UdpStub {
	key := c.key(src, dst)
	v, ok := c.ustubs.Load(key)
	if ok {
		return v.(*UdpStub)
	}

	// Fallback lookup: if remote server replied with resolved IP while
	// the client originally sent a domain, match by client src and target port
	var match *UdpStub
	srcStr := src.String()
	c.ustubs.Range(func(_, value any) bool {
		ustub, ok := value.(*UdpStub)
		if ok && ustub.srcAddress().String() == srcStr && ustub.dstAddress().Port == dst.Port {
			match = ustub
			return false
		}
		return true
	})

	return match
}

func (c *UdpCache) keepalive() {
	if time.Since(c.lastKeepalive) < udpCacheKeepaliveTime {
		return
	}
	c.lastKeepalive = time.Now()

	deleteUstubs := make([]*UdpStub, 0)
	c.ustubs.Range(func(key, value any) bool {
		ustub, ok := value.(*UdpStub)
		if ok {
			if ustub.tnl.idleTimeout > 0 && time.Since(time.Unix(0, ustub.lastActvity.Load())) >= ustub.tnl.idleTimeout {
				deleteUstubs = append(deleteUstubs, ustub)
			}
		}
		return true
	})

	for _, ustub := range deleteUstubs {
		ustub.close()
		key := c.key(ustub.srcAddress(), ustub.dstAddress())
		c.ustubs.Delete(key)
		log.Debugf("delete UDPConn src %s dst %s", ustub.srcAddress().String(), ustub.dstAddress().String())
	}
}

func (c *UdpCache) key(src, dst *UDPAddr) string {
	if len(dst.Domain) > 0 {
		return fmt.Sprintf("%s->%s:%d", src.String(), dst.Domain, dst.Port)
	}
	return fmt.Sprintf("%s->%s", src.String(), dst.String())
}

func (c *UdpCache) cleanup() {
	c.ustubs.Range(func(key, value any) bool {
		ustub, ok := value.(*UdpStub)
		if ok {
			ustub.close()
			c.ustubs.CompareAndDelete(key, ustub)
		}
		return true
	})
}
