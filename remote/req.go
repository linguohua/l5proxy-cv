package remote

import (
	"l5proxy_cv/meta"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	tcpSocketWriteDeadline = 5
)

type ReqContext struct {
	From string
	To   string

	ServiceTime time.Duration

	FromBytes int64
	ToBytes   int64
}

type Req struct {
	isUsed bool
	idx    uint16
	tag    uint16

	owner *WSTunnel

	conn meta.TCPConn

	ctx *ReqContext
}

func newReq(t *WSTunnel, idx uint16) *Req {
	return &Req{
		owner:  t,
		idx:    idx,
		tag:    0,
		isUsed: false,
	}
}

// free should be called by Reqq only, lock() must be called first
func (r *Req) free() {
	if r.conn != nil {
		r.conn.Close()
	}
}

func (r *Req) onServerData(data []byte, withlog bool) error {
	// if write failed, return an error, outer should free this request
	conn := r.conn
	if conn != nil {
		if len(data) > 0 {
			r.touch()
		}
		wrote := 0
		l := len(data)
		for {
			conn.SetWriteDeadline(time.Now().Add(tcpSocketWriteDeadline * time.Second))
			n, err := conn.Write(data[wrote:])
			if err != nil {
				return err
			}

			wrote = wrote + n
			if wrote == l {
				ctx := r.ctx
				if ctx != nil {
					ctx.ToBytes = ctx.ToBytes + int64(wrote)

					if withlog {
						log.Infof("[%s] --> [%s], bytes:%d", ctx.To, ctx.From, l)
					}
				}

				break
			}
		}
	} else {
		log.Errorf("onServerData error: null conn, idx:%d", r.idx)
	}

	return nil
}

func (r *Req) onSeverHalfClosed() {
	conn := r.conn
	if conn != nil {
		err := conn.CloseWrite()
		if err != nil {
			log.Errorf("onSeverHalfClosed error: %v, idx:%d", err, r.idx)
		}
	}
}

func (r *Req) proxy() {
	conn := r.conn

	if conn == nil {
		return
	}

	r.touch()
	buf := make([]byte, 16*1024) // 16K
	for {
		n, err := conn.Read(buf)

		if !r.isUsed {
			// request is free!
			log.Infof("proxy read, request is free, discard data, len:%d", n)
			break
		}

		// owner never be null
		owner := r.owner

		if err != nil {
			// log.Println("proxy read failed:", err)
			owner.onClientTerminate(r.idx, r.tag)
			break
		}

		if n == 0 {
			// log.Println("proxy read, server half close")
			owner.onClientHalfClosed(r.idx, r.tag)
			break
		}

		r.touch()
		now := time.Now()

		owner.onClientReqData(r.idx, r.tag, buf[:n])

		ctx := r.ctx
		elapsed := time.Since(now).Round(time.Millisecond)
		if ctx != nil {
			ctx.FromBytes = ctx.FromBytes + int64(n)
			log.Infof("req [%s] --> [%s] tranfor bytes:%d, time:%s", ctx.From, ctx.To, n, elapsed)
		}
	}
}

// touch extends the shared bidirectional idle deadline, not the write timeout.
func (r *Req) touch() {
	if r.owner.idleTimeout > 0 && r.conn != nil {
		r.conn.SetReadDeadline(time.Now().Add(r.owner.idleTimeout))
	}
}
