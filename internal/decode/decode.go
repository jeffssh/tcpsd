package decode

import (
	"bufio"
	"fmt"
	"io"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// Manager implements tcpassembly.StreamFactory to handle new TCP sessions.
type Manager struct {
	count int
}

// New creates a new Handler for a new TCP session's reassembled data.
func (m *Manager) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	m.count += 1

	h := NewHandler(m.count, netFlow, tcpFlow)
	return h.stream
}

// Handler parses the TCP data on a single stream into HTTP packets.
//
// Each time tcpassembly.StreamPool encounters a new TCP session, it will have
// the Factory create a new Handler to read the data on the stream.
type Handler struct {
	stream *tcpreader.ReaderStream
	c      chan []byte
	id     int
	flow   string
}

// NewHandler creates a new Handler to decode a TCP stream.
//
// Using a Manager to create new Handlers should be used instead of this method.
func NewHandler(id int, net, tcp gopacket.Flow) *Handler {
	s := tcpreader.NewReaderStream()
	h := &Handler{
		stream: &s,
		c:      make(chan []byte),
		id:     id,
		flow:   fmt.Sprintf("%v:%v 🡒 %v:%v", net.Src(), tcp.Src(), net.Dst(), tcp.Dst()),
	}
	go h.Run()
	return h
}

// Run processes the data from the Handler's TCP stream.
func (h *Handler) Run() {
	streambuf := bufio.NewReader(h.stream)
	_, err := io.ReadAll(streambuf)
	if err != nil {
		fmt.Printf("[ERROR] %s: failed to read from TCP stream: %v\n", h, err)
		return
	}
}

func (h *Handler) String() string {
	return fmt.Sprintf("id=%d %s", h.id, h.flow)
}
