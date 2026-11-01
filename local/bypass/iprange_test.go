package localbypass

import "testing"

func TestXxx(t *testing.T) {
	ipstrs := []string{
		"127.0.0.1", "127.0.0.4", "127.0.1.1", "127.255.255.254",
		"10.0.0.1", "10.0.1.1", "10.1.1.1",
		"192.168.0.1", "192.168.10.1",
	}

	for _, ipstr := range ipstrs {
		if !isStringLocalIP4(ipstr) {
			t.Errorf("expected %s to be local IP4, but was not", ipstr)
		}
	}
}

func TestDomainIn(t *testing.T) {
	whitelist := make(map[string]struct{})
	whitelist["cn"] = struct{}{}
	whitelist["weibo.com"] = struct{}{}
	whitelist["163.com"] = struct{}{}

	domains := []string{"sina.com.cn", "163.com", "weibo.com", "mail.163.com", "passport.weibo.com"}

	for _, dn := range domains {
		if !isDomainIn(dn, whitelist) {
			t.Fail()
		}
	}
}
