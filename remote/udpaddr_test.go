package remote

import (
	"net"
	"testing"
)

func TestUDPAddrIPv4(t *testing.T) {
	addr := &UDPAddr{
		IP:   net.ParseIP("192.168.1.100"),
		Port: 8080,
	}

	encoded := addr.WriteAddress()
	if len(encoded) != 7 {
		t.Fatalf("expected length 7 for IPv4, got %d", len(encoded))
	}

	decoded, consumed, err := ParseUDPAddr(encoded)
	if err != nil {
		t.Fatalf("ParseUDPAddr failed: %v", err)
	}
	if consumed != 7 {
		t.Fatalf("expected consumed 7, got %d", consumed)
	}
	if decoded.Port != 8080 {
		t.Fatalf("expected port 8080, got %d", decoded.Port)
	}
	if decoded.IP.String() != "192.168.1.100" {
		t.Fatalf("expected IP 192.168.1.100, got %s", decoded.IP.String())
	}
	if decoded.Domain != "" {
		t.Fatalf("expected empty domain, got %s", decoded.Domain)
	}
}

func TestUDPAddrDomain(t *testing.T) {
	addr := &UDPAddr{
		Domain: "dns.google",
		Port:   53,
	}

	// Scheme A: Port(2 bytes LE) + ipType(0x01) + domainLen(1 byte) + domainName(bytes)
	encoded := addr.WriteAddress()
	expectedLen := 2 + 1 + 1 + len("dns.google")
	if len(encoded) != expectedLen {
		t.Fatalf("expected length %d, got %d", expectedLen, len(encoded))
	}

	if encoded[2] != 1 {
		t.Fatalf("expected ipType 1, got %d", encoded[2])
	}
	if int(encoded[3]) != len("dns.google") {
		t.Fatalf("expected domain len %d, got %d", len("dns.google"), encoded[3])
	}

	decoded, consumed, err := ParseUDPAddr(encoded)
	if err != nil {
		t.Fatalf("ParseUDPAddr failed: %v", err)
	}
	if consumed != expectedLen {
		t.Fatalf("expected consumed %d, got %d", expectedLen, consumed)
	}
	if decoded.Port != 53 {
		t.Fatalf("expected port 53, got %d", decoded.Port)
	}
	if decoded.Domain != "dns.google" {
		t.Fatalf("expected domain dns.google, got %s", decoded.Domain)
	}
}

func TestUDPAddrIPv6(t *testing.T) {
	addr := &UDPAddr{
		IP:   net.ParseIP("2001:4860:4860::8888"),
		Port: 53,
	}

	encoded := addr.WriteAddress()
	if len(encoded) != 19 {
		t.Fatalf("expected length 19 for IPv6, got %d", len(encoded))
	}
	if encoded[2] != 2 {
		t.Fatalf("expected ipType 2, got %d", encoded[2])
	}

	decoded, consumed, err := ParseUDPAddr(encoded)
	if err != nil {
		t.Fatalf("ParseUDPAddr failed: %v", err)
	}
	if consumed != 19 {
		t.Fatalf("expected consumed 19, got %d", consumed)
	}
	if decoded.Port != 53 {
		t.Fatalf("expected port 53, got %d", decoded.Port)
	}
	if decoded.IP.String() != "2001:4860:4860::8888" {
		t.Fatalf("expected IP 2001:4860:4860::8888, got %s", decoded.IP.String())
	}
}
