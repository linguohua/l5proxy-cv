package localhttp

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"l5proxy_cv/meta"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// HTTP/HTTPS config
// HTTPS self-signed certificate:
//
//	use the following command to generate a chrome acceptable self-signed certificate
//
//	openssl req -newkey rsa:2048 -x509 -nodes -keyout localhost.key -new -out localhost.crt -subj /CN=localhost -reqexts SAN -extensions SAN -config <(cat /etc/ssl/openssl.cnf \
//	   <(printf '[SAN]\nsubjectAltName=DNS:localhost,IP:127.0.0.1')) -sha256 -days 3650
//
//	on-ubuntu:
//		echo '/home/abc/localhost.crt' | sudo tee -a /etc/ca-certificates.conf
//		sudo update-ca-certificates
//
// on-windows:
//
//	import as a root certificate
type LocalConfig struct {
	Address string

	HTTPsAddr string
	Keyfile   string
	Certfile  string

	UseBypass bool

	TransportHandler meta.HTTPSocks5TransportHandler
	BypassHandler    meta.Bypass
}

type Mgr struct {
	cfg LocalConfig

	defaultHandler *requestHandler
	server         *http.Server
	httpsServer    *http.Server
}

type httpconn struct {
	net.Conn

	tcpc *net.TCPConn
}

func (hc httpconn) ID() *stack.TransportEndpointID {
	return nil
}

func (hc httpconn) CloseWrite() error {
	if hc.tcpc != nil {
		return hc.tcpc.CloseWrite()
	}
	return nil
}

func (hc httpconn) CloseRead() error {
	if hc.tcpc != nil {
		return hc.tcpc.CloseRead()
	}
	return nil
}

type requestHandler struct {
	mgr *Mgr
}

func getTargetPortOrDefault(uurl *url.URL) int {
	portStr := uurl.Port()
	if len(portStr) > 0 {
		port, _ := strconv.Atoi(portStr)
		return port
	}

	switch uurl.Scheme {
	case "http":
		return 80
	case "https":
		return 443
	case "ws":
		return 80
	case "wss":
		return 443
	}

	return 80
}

func drainBuffered(bufrw *bufio.ReadWriter) ([]byte, error) {
	buffered := bufrw.Reader.Buffered()
	extraBytes := make([]byte, buffered)
	n, err := bufrw.Reader.Read(extraBytes)
	if err != nil {
		return nil, fmt.Errorf("localhttp.drainBuffered read bufrw failed:%s", err)
	}

	if n != buffered {
		return nil, fmt.Errorf("localhttp.ServeHTTP read bufrw not match, expected:%d, read:%d", buffered, n)
	}

	return extraBytes, nil
}

func rebuildHTTPHeaders(r *http.Request) strings.Builder {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s %s", r.Method, r.URL.Path))
	if len(r.URL.RawQuery) > 0 {
		b.WriteString(fmt.Sprintf("?%s", r.URL.RawQuery))
	}

	if len(r.URL.RawFragment) > 0 {
		b.WriteString(fmt.Sprintf("#%s", r.URL.RawFragment))
	}

	b.WriteString(fmt.Sprintf(" HTTP/%d.%d\r\n", r.ProtoMajor, r.ProtoMinor))
	b.WriteString(fmt.Sprintf("Host: %s\r\n", r.Host))
	for k, v := range r.Header {
		for _, vv := range v {
			b.WriteString(fmt.Sprintf("%s: %s\r\n", k, vv))
		}
	}
	b.WriteString("\r\n")
	return b
}

func setTCPKeepAlive(conn net.Conn) *net.TCPConn {
	var tcpConn *net.TCPConn
	tlsconn, ok := conn.(*tls.Conn)
	if ok {
		tcpConn, ok = tlsconn.NetConn().(*net.TCPConn)
		if !ok {
			return nil
		}
	} else {
		tcpConn, ok = conn.(*net.TCPConn)
		if !ok {
			return nil
		}
	}

	if tcpConn != nil {
		tcpConn.SetKeepAlivePeriod(5 * time.Second)
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
	}

	return tcpConn
}

func (rh *requestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Info("localhttp.ServeHTTP Response doesn't support hijacking")
		http.Error(w, "HTTP Response doesn't support hijacking", http.StatusInternalServerError)
		return
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		log.Infof("localhttp.ServeHTTP Hijack failed:%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var handled = false
	defer func() {
		if !handled {
			conn.Close()
		}
	}()

	targetInfo := &meta.HTTPSocksTargetInfo{}
	var tcpConn = setTCPKeepAlive(conn)

	uurl := r.URL
	targetHost := uurl.Hostname()
	targetPort := getTargetPortOrDefault(uurl)
	if targetHost == "" {
		if host, portStr, splitErr := net.SplitHostPort(r.Host); splitErr == nil {
			targetHost = host
			if p, parseErr := strconv.Atoi(portStr); parseErr == nil {
				targetPort = p
			}
		} else {
			targetHost = r.Host
		}
	}
	targetInfo.DomainName = targetHost
	targetInfo.Port = targetPort

	var extraBytes []byte

	if r.Method == http.MethodConnect {
		log.Info("localhttp.ServeHTTP MethodConnect")
		// CONNECT request
		// write a reply to client
		bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n" +
			"Proxy-agent: l5proxy\r\n" +
			"\r\n")
		bufrw.Flush()
		buffered := bufrw.Reader.Buffered()
		if buffered > 0 {
			extraBytes, err = drainBuffered(bufrw)
			if err != nil {
				log.Errorf("localhttp.ServeHTTP error: %s", err)
				return
			}
		}
	} else {
		log.Info("localhttp.ServeHTTP normal request")
		// normal request
		builder := rebuildHTTPHeaders(r)
		buffered := bufrw.Reader.Buffered()
		extraBytes = make([]byte, builder.Len()+buffered)
		copy(extraBytes, []byte(builder.String()))

		if buffered > 0 {
			var bufrwBytes []byte
			bufrwBytes, err = drainBuffered(bufrw)
			if err != nil {
				log.Errorf("localhttp.ServeHTTP error: %s", err)
				return
			}
			copy(extraBytes[builder.Len():], bufrwBytes)
		}
	}

	targetInfo.ExtraBytes = extraBytes

	cfg := rh.mgr.cfg
	if cfg.UseBypass && cfg.BypassHandler != nil {
		bypass := cfg.BypassHandler
		if bypass.BypassAble(targetInfo.DomainName) {
			bypass.HandleHttpSocks5TCP(httpconn{Conn: conn, tcpc: tcpConn}, targetInfo)
			handled = true
		}
	}

	if !handled {
		thandler := cfg.TransportHandler
		thandler.HandleHttpSocks5TCP(httpconn{Conn: conn, tcpc: tcpConn}, targetInfo)
		handled = true
	}
}

func NewMgr(cfg *LocalConfig) meta.Local {
	mgr := &Mgr{
		cfg: *cfg,
	}

	return mgr
}

func (mgr *Mgr) Name() string {
	return "httpmode"
}

func (mgr *Mgr) Startup() error {
	if mgr.server != nil {
		return fmt.Errorf("localhttp.Mgr already startup")
	}

	mgr.defaultHandler = &requestHandler{
		mgr: mgr,
	}

	mgr.server = &http.Server{Addr: mgr.cfg.Address, Handler: mgr.defaultHandler}
	log.Infof("HTTP server startup, address:%s", mgr.cfg.Address)

	if mgr.cfg.HTTPsAddr != "" {
		mgr.httpsServer = &http.Server{Addr: mgr.cfg.HTTPsAddr, Handler: mgr.defaultHandler,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler))} // only support HTTP/1.1, no HTTP/2
		log.Infof("HTTPS server startup, address:%s", mgr.cfg.HTTPsAddr)
	}

	go mgr.serveHTTP()
	if mgr.httpsServer != nil {
		go mgr.serveHTTPs()
	}

	return nil
}

func (mgr *Mgr) Shutdown() error {
	if mgr.server == nil {
		return fmt.Errorf("localhttp.Mgr isn't running")
	}

	ctx, cancel := context.WithTimeout(context.TODO(), 3*time.Second)
	defer cancel()
	err := mgr.server.Shutdown(ctx)
	if err != nil {
		log.Errorf("localhttp.Mgr shutdown http server failed:%s", err)
	}

	if mgr.httpsServer != nil {
		httpsErr := mgr.httpsServer.Shutdown(ctx)
		if httpsErr != nil {
			log.Errorf("localhttp.Mgr shutdown https server failed:%s", httpsErr)
		}
		mgr.httpsServer = nil
	}
	mgr.server = nil

	log.Info("HTTP server shutdown")

	return nil
}

func (mgr *Mgr) serveHTTP() {
	err := mgr.server.ListenAndServe()
	if err != nil {
		log.Errorf("localhttp.Mgr ListenAndServe error:%s", err)
	}
}

func (mgr *Mgr) serveHTTPs() {
	err := mgr.httpsServer.ListenAndServeTLS(mgr.cfg.Certfile, mgr.cfg.Keyfile)
	if err != nil {
		log.Errorf("localhttp.Mgr ListenAndServeTLS error:%s", err)
	}
}
