package localsocks5

import (
	"encoding/binary"
	"io"
	"l5proxy_cv/meta"
	"net"
	"testing"
	"time"
)

type mockUDPTransportHandler struct {
	handledCh chan struct{}
	lastConn  meta.UDPConn
	lastExtra []byte
}

func (m *mockUDPTransportHandler) HandleUDP(conn meta.UDPConn, extra []byte) {
	m.lastConn = conn
	m.lastExtra = extra
	if m.handledCh != nil {
		m.handledCh <- struct{}{}
	}

	// Echo back a response with "pong-" prefix
	resp := append([]byte("pong-"), extra...)
	_, _ = conn.WriteTo(resp, nil)
}

func TestSocks5UDPAssociateDomain(t *testing.T) {
	mockHandler := &mockUDPTransportHandler{
		handledCh: make(chan struct{}, 1),
	}

	cfg := &LocalConfig{
		Address:             "127.0.0.1:0",
		UDPTransportHandler: mockHandler,
	}

	mgrObj := NewMgr(cfg)
	mgr := mgrObj.(*Mgr)
	err := mgr.Startup()
	if err != nil {
		t.Fatalf("Startup failed: %v", err)
	}
	defer mgr.Shutdown()

	serverAddr := mgr.listener.Addr().String()

	// 1. Connect TCP to SOCKS5 server
	tcpConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("Dial TCP failed: %v", err)
	}
	defer tcpConn.Close()

	// 2. Auth handshake: VER 5, 1 method, 0x00 (noAuth)
	_, err = tcpConn.Write([]byte{socks5Version, 1, noAuth})
	if err != nil {
		t.Fatalf("Write auth failed: %v", err)
	}
	authResp := make([]byte, 2)
	_, err = io.ReadFull(tcpConn, authResp)
	if err != nil {
		t.Fatalf("Read auth response failed: %v", err)
	}
	if authResp[0] != socks5Version || authResp[1] != noAuth {
		t.Fatalf("Auth failed: %v", authResp)
	}

	// 3. Send associateCommand (CMD 3)
	// VER 5, CMD 3, RSV 0, ATYP 1 (IPv4), 0.0.0.0, Port 0
	reqBuf := []byte{socks5Version, associateCommand, 0, ipv4Address, 0, 0, 0, 0, 0, 0}
	_, err = tcpConn.Write(reqBuf)
	if err != nil {
		t.Fatalf("Write associate request failed: %v", err)
	}

	// Read reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
	replyBuf := make([]byte, 10)
	_, err = io.ReadFull(tcpConn, replyBuf)
	if err != nil {
		t.Fatalf("Read associate reply failed: %v", err)
	}
	if replyBuf[1] != successReply {
		t.Fatalf("Associate command failed with REP: %d", replyBuf[1])
	}

	relayIP := net.IP(replyBuf[4:8])
	relayPort := binary.BigEndian.Uint16(replyBuf[8:10])
	relayUDPAddr := &net.UDPAddr{IP: relayIP, Port: int(relayPort)}

	// 4. Create client UDP socket
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer clientUDP.Close()

	// 5. Send SOCKS5 UDP datagram with Domain:
	// RSV(2)=00 00, FRAG(1)=00, ATYP(1)=03, LEN(1)=len("my-domain.com"), "my-domain.com", Port(2)=53, Data="ping"
	targetDomain := "my-domain.com"
	targetPort := uint16(53)
	payload := []byte("ping")

	udpHeader := make([]byte, 7+len(targetDomain))
	udpHeader[0] = 0
	udpHeader[1] = 0
	udpHeader[2] = 0
	udpHeader[3] = fqdnAddress // 0x03
	udpHeader[4] = byte(len(targetDomain))
	copy(udpHeader[5:], []byte(targetDomain))
	binary.BigEndian.PutUint16(udpHeader[5+len(targetDomain):], targetPort)

	udpPacket := append(udpHeader, payload...)
	_, err = clientUDP.WriteToUDP(udpPacket, relayUDPAddr)
	if err != nil {
		t.Fatalf("WriteToUDP failed: %v", err)
	}

	// 6. Wait for mock handler to be called
	select {
	case <-mockHandler.handledCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for mockHandler.HandleUDP")
	}

	if mockHandler.lastConn.TargetDomain() != targetDomain {
		t.Fatalf("expected TargetDomain %s, got %s", targetDomain, mockHandler.lastConn.TargetDomain())
	}
	if string(mockHandler.lastExtra) != "ping" {
		t.Fatalf("expected extra 'ping', got '%s'", string(mockHandler.lastExtra))
	}

	// 7. Client reads response from UDP socket
	clientUDP.SetReadDeadline(time.Now().Add(2 * time.Second))
	respBuf := make([]byte, 1024)
	n, _, err := clientUDP.ReadFromUDP(respBuf)
	if err != nil {
		t.Fatalf("ReadFromUDP failed: %v", err)
	}

	if n < 7+len(targetDomain) {
		t.Fatalf("response too short: %d", n)
	}
	if respBuf[3] != fqdnAddress {
		t.Fatalf("expected response ATYP 3, got %d", respBuf[3])
	}
	dLen := int(respBuf[4])
	if string(respBuf[5:5+dLen]) != targetDomain {
		t.Fatalf("expected response domain %s, got %s", targetDomain, string(respBuf[5:5+dLen]))
	}
	respPort := binary.BigEndian.Uint16(respBuf[5+dLen : 7+dLen])
	if respPort != targetPort {
		t.Fatalf("expected response port %d, got %d", targetPort, respPort)
	}
	respPayload := string(respBuf[7+dLen : n])
	if respPayload != "pong-ping" {
		t.Fatalf("expected payload 'pong-ping', got '%s'", respPayload)
	}
}

func TestSocks5UDPAssociateIPv4AndSubsequentPackets(t *testing.T) {
	mockHandler := &mockUDPTransportHandler{
		handledCh: make(chan struct{}, 1),
	}

	cfg := &LocalConfig{
		Address:             "127.0.0.1:0",
		UDPTransportHandler: mockHandler,
	}

	mgrObj := NewMgr(cfg)
	mgr := mgrObj.(*Mgr)
	err := mgr.Startup()
	if err != nil {
		t.Fatalf("Startup failed: %v", err)
	}
	defer mgr.Shutdown()

	serverAddr := mgr.listener.Addr().String()

	tcpConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("Dial TCP failed: %v", err)
	}
	defer tcpConn.Close()

	// Auth handshake
	_, _ = tcpConn.Write([]byte{socks5Version, 1, noAuth})
	authResp := make([]byte, 2)
	_, _ = io.ReadFull(tcpConn, authResp)

	// Associate command
	_, _ = tcpConn.Write([]byte{socks5Version, associateCommand, 0, ipv4Address, 0, 0, 0, 0, 0, 0})
	replyBuf := make([]byte, 10)
	_, _ = io.ReadFull(tcpConn, replyBuf)

	relayIP := net.IP(replyBuf[4:8])
	relayPort := binary.BigEndian.Uint16(replyBuf[8:10])
	relayUDPAddr := &net.UDPAddr{IP: relayIP, Port: int(relayPort)}

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer clientUDP.Close()

	// Send Packet 1: target 8.8.8.8:53, payload "pkt1"
	targetIP := net.ParseIP("8.8.8.8").To4()
	targetPort := uint16(53)

	makePacket := func(payload []byte) []byte {
		header := make([]byte, 10)
		header[0] = 0
		header[1] = 0
		header[2] = 0
		header[3] = ipv4Address
		copy(header[4:8], targetIP)
		binary.BigEndian.PutUint16(header[8:10], targetPort)
		return append(header, payload...)
	}

	_, err = clientUDP.WriteToUDP(makePacket([]byte("pkt1")), relayUDPAddr)
	if err != nil {
		t.Fatalf("WriteToUDP failed: %v", err)
	}

	select {
	case <-mockHandler.handledCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for HandleUDP pkt1")
	}

	if mockHandler.lastConn.TargetDomain() != "" {
		t.Fatalf("expected empty domain for IPv4")
	}
	if string(mockHandler.lastExtra) != "pkt1" {
		t.Fatalf("expected extra 'pkt1', got '%s'", string(mockHandler.lastExtra))
	}

	// Send Packet 2: same target 8.8.8.8:53, payload "pkt2"
	_, err = clientUDP.WriteToUDP(makePacket([]byte("pkt2")), relayUDPAddr)
	if err != nil {
		t.Fatalf("WriteToUDP failed: %v", err)
	}

	// Read Packet 2 from virtual conn's Read() method
	pkt2Buf := make([]byte, 1024)
	n, err := mockHandler.lastConn.Read(pkt2Buf)
	if err != nil {
		t.Fatalf("vconn.Read failed: %v", err)
	}
	if string(pkt2Buf[:n]) != "pkt2" {
		t.Fatalf("expected 'pkt2', got '%s'", string(pkt2Buf[:n]))
	}

	// Write back response for pkt2
	_, _ = mockHandler.lastConn.WriteTo([]byte("pong-pkt2"), nil)

	// Client reads response from UDP socket
	clientUDP.SetReadDeadline(time.Now().Add(2 * time.Second))
	respBuf := make([]byte, 1024)
	n, _, err = clientUDP.ReadFromUDP(respBuf)
	if err != nil {
		t.Fatalf("ReadFromUDP failed: %v", err)
	}
	if n < 10 {
		t.Fatalf("response too short: %d", n)
	}
	if respBuf[3] != ipv4Address {
		t.Fatalf("expected ATYP 1, got %d", respBuf[3])
	}
	respPayload := string(respBuf[10:n])
	if respPayload != "pong-pkt1" && respPayload != "pong-pkt2" {
		t.Fatalf("expected pong-pkt, got '%s'", respPayload)
	}
}

