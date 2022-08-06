package capture

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/jeffssh/tcpsd/decode"
)

type CaptureConfig struct {
	Interface string
	BPFFilter string
	SnapLen   int
}

// Start begins capturing packets on the specified interface.
//
// The capture will halt when the parent context is canceled.
func Start(ctx context.Context, cfg *CaptureConfig) error {
	if _, err := net.InterfaceByName(cfg.Interface); err != nil {
		return fmt.Errorf("invalid interface name %q: %v", cfg.Interface, err)
	}

	handle, err := pcap.OpenLive(cfg.Interface, int32(cfg.SnapLen), true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %q: %v", cfg.Interface, err)
	}
	if err := handle.SetBPFFilter(cfg.BPFFilter); err != nil {
		return fmt.Errorf("failed to set BPF BPFFilter to %q: %v", cfg.BPFFilter, err)
	}

	pool := tcpassembly.NewStreamPool(decode.NewManager(ctx))
	asm := tcpassembly.NewAssembler(pool)

	psrc := gopacket.NewPacketSource(handle, handle.LinkType())
	pchan := psrc.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case pkt := <-pchan:
			if pkt == nil {
				return nil
			}
			if pkt.NetworkLayer() == nil || pkt.TransportLayer() == nil {
				continue
			}
			tcp := pkt.TransportLayer().(*layers.TCP)
			asm.AssembleWithTimestamp(pkt.NetworkLayer().NetworkFlow(), tcp, pkt.Metadata().Timestamp)
		case <-ticker:
			// Flush connections that have been invactive for over 2 minutes.
			asm.FlushOlderThan(time.Now().Add(time.Minute * -2))
		case <-ctx.Done():
			return nil
		}
	}
}
