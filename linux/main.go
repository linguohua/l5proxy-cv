package main

import (
	"flag"
	"fmt"
	"lproxy_tun/config"
	"lproxy_tun/xy"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"

	log "github.com/sirupsen/logrus"
)

func openTun() (int, error) {
	name := "tun0xy"

	if len(name) >= unix.IFNAMSIZ {
		return -1, fmt.Errorf("interface name too long: %s", name)
	}

	fd, err := tun.Open(name)
	if err != nil {
		return -1, fmt.Errorf("create tun: %w", err)
	}

	return fd, nil
}

func main() {
	// for debug
	var configFile string
	flag.StringVar(&configFile, "c", "", "Config file path")
	flag.Parse()

	cfg, err := config.ParseConfig(configFile)
	if err != nil {
		log.Fatal(err)
	}

	log.SetLevel(log.DebugLevel)

	fd, err := openTun()
	if err != nil {
		log.Fatal(err)
	}

	err = xy.Singleton().Startup(fd, 1500, cfg)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		err = xy.Singleton().Shutdown()
		if err != nil {
			log.Fatal(err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
