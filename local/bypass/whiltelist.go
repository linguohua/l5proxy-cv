package localbypass

import (
	"bufio"
	"fmt"
	"encoding/json"
	"io"
	"l5proxy_cv/mydns"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

func loadWhitelist(dnsResolver *mydns.AlibbResolver0, protector func(uint64), uurl string) (map[string]struct{}, error) {
	tr := &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return mydns.DialWithProtector(dnsResolver, protector, nil, network, addr)
		},
	}

	client := http.Client{Transport: tr}

	rsp, err := client.Get(uurl)
	if err != nil {
		return nil, err
	}

	defer rsp.Body.Close()

	if rsp.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(rsp.Body)
		if err != nil {
			return nil, err
		}

		bodyString := string(bodyBytes)
		reader := bufio.NewReader(strings.NewReader(bodyString))
		whitelist := make(map[string]struct{})
		for {
			linebytes, isPrefix, err := reader.ReadLine()
			if err != nil {
				if err == io.EOF {
					break
				}

				return nil, err
			}

			if isPrefix {
				return nil, fmt.Errorf("loadWhitelist failed, underlying buffer is too small")
			}

			domain := strings.TrimSpace(string(linebytes))
			if len(domain) > 0 {
				whitelist[domain] = struct{}{}
			}
		}

		log.Infof("localbypass.Mgr load whilte domain name count: %d", len(whitelist))
		return whitelist, nil
	} else {
		return nil, fmt.Errorf("rsp status code %d != 200", rsp.StatusCode)
	}
}

func (mgr *Mgr) loadWhitelist() {
	var host string
	url, err := url.Parse(mgr.cfg.WhitelistURL)
	if err != nil {
		log.Errorf("NewMgr parse URL failed:%s", err)
		host = "127.0.0.1"
	} else {
		host = url.Host
	}

	dnsResolver := mydns.NewAlibbResolver(mgr.cfg.AliDNS, host, mgr.cfg.Protector)

	for {
		m, err := loadWhitelist(dnsResolver, mgr.cfg.Protector, mgr.cfg.WhitelistURL)
		if err != nil {
			log.Errorf("localbypass load white list failed:%s", err)
			time.Sleep(60 * time.Second)
			continue
		}

		mgr.whitelistLock.Lock()
		mgr.whitelist = m
		mgr.whitelistLock.Unlock()
		break
	}
}

func loadBlacklistFile(filePath string) (map[string]struct{}, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read blacklist file failed: %w", err)
	}

	var hosts []string
	if err := json.Unmarshal(data, &hosts); err != nil {
		return nil, fmt.Errorf("parse blacklist JSON failed: %w", err)
	}

	blacklist := make(map[string]struct{})
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if len(host) > 0 {
			blacklist[host] = struct{}{}
		}
	}

	return blacklist, nil
}
