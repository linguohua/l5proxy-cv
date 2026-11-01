package mydns

import (
	"testing"
)

func TestResolve(t *testing.T) {
	ip, err := resolveHost4("223.5.5.5:53", "alidns.com", nil)
	if err != nil {
		t.Skipf("DNS resolution skipped (network or server unavailable): %v", err)
	}

	if ip == nil {
		t.Fatalf("expected resolved IP, got nil")
	}

	t.Logf("DNS reply for alidns.com: %s", ip.String())
}
