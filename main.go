package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/jeffssh/tcpsd/capture"
)

var cfg = new(capture.CaptureConfig)

func init() {
	flag.StringVar(&cfg.Interface, "i", "eth0", "Interface to get packets from")
	flag.StringVar(&cfg.BPFFilter, "f", "tcp and dst port 80", "BPF filter for pcap")
	flag.IntVar(&cfg.SnapLen, "s", 1600, "SnapLen for pcap packet capture")
}

func main() {
	flag.Parse()

	fmt.Printf("[+] Listening on interface %q with filter %q\n", cfg.Interface, cfg.BPFFilter)
	if err := capture.Start(context.Background(), cfg); err != nil {
		log.Fatalf("[!] Capture failed to start: %v", err)
	}
}
