package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var iface = flag.String("i", "eth0", "Interface to get packets from")
var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp and dst port 80", "BPF filter for pcap")
var packetCount = 0
var logger *log.Logger

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

// streamFactory implements tcpassembly.StreamFactory
type streamFactory struct{}

// stream will handle the actual decoding of tcp packets.
type stream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *streamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	s := &stream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go s.run(packetCount) // Important... we must guarantee that data from the reader stream is read.
	packetCount += 1
	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &s.r
}

func (h *stream) run(streamNumber int) {
	var httpRequestbuf, httpResponsebuf bytes.Buffer
	mw := io.MultiWriter(&httpRequestbuf, &httpResponsebuf)
	byteReader := bufio.NewReader(io.TeeReader(&h.r, mw))
	banner := "============== tcp packet %d =============="
	readSomethingStructured := false
	for {
		data, err := io.ReadAll(byteReader)
		if err != nil {
			logger.Println("Error reading raw bytes from stream", h.net, h.transport, ":", err)
		} else if len(data) == 0 {
			continue
		}
		httpReqReader := bufio.NewReader(&httpRequestbuf)
		req, err := http.ReadRequest(httpReqReader)
		if err == io.EOF {
			return
		} else if err == nil {
			reqData, err := httputil.DumpRequest(req, true)
			if err != nil {
				logger.Println("error dumping request:", err)
			} else {
				logger.Printf(banner+"\n%s"+banner, streamNumber, string(reqData), streamNumber)
				readSomethingStructured = true
			}
		}
		httpRespReader := bufio.NewReader(&httpResponsebuf)
		resp, err := http.ReadResponse(httpRespReader, nil)
		if err == io.EOF {
			return
		} else if err == nil {
			respData, err := httputil.DumpResponse(resp, true)
			if err != nil {
				fmt.Println("error dumping response:", err)
			} else {
				logger.Printf(banner+"\n%s"+banner, streamNumber, string(respData), streamNumber)
				readSomethingStructured = true
			}
		}
		// last attempt to print
		if !readSomethingStructured {
			fmt.Printf("============== tcp stream %d data ==============\n", streamNumber)
			fmt.Print(hex.Dump(data))
			fmt.Printf("============== tcp stream %d data ==============\n", streamNumber)
		}
	}
}

func main() {
	logger = log.New(os.Stdout, "", 0)
	defer util.Run()()
	var handle *pcap.Handle
	var err error

	// Set up pcap packet capture
	logger.Printf("listening on interface %s with filter %s\n", *iface, *filter)
	handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)

	if err != nil {
		logger.Fatal(err)
	}

	if err := handle.SetBPFFilter(*filter); err != nil {
		logger.Fatal(err)
	}

	// Set up assembly
	streamFactory := &streamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}
