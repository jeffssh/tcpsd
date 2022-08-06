package decode

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/alecthomas/chroma/quick"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var (
	httpTokens = map[string]bool{
		"GET":      true,
		"HEAD":     true,
		"POST":     true,
		"PUT":      true,
		"PATCH":    true,
		"DELETE":   true,
		"CONNECT":  true,
		"OPTIONS":  true,
		"TRACE":    true,
		"HTTP/1.0": true,
		"HTTP/1.1": true,
	}
)

// Manager implements tcpassembly.StreamFactory to handle new TCP sessions.
type Manager struct {
	count  int
	output chan string
}

// NewManager initializes a new stream handler factory.
func NewManager(ctx context.Context) *Manager {
	m := &Manager{0, make(chan string)}
	go func() {
		for {
			select {
			case s := <-m.output:
				fmt.Println(s)
			case <-ctx.Done():
				break
			}
		}
	}()
	return m
}

// New creates a new Handler for a new TCP session's reassembled data.
func (m *Manager) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	m.count++
	h := NewHandler(m.count, netFlow, tcpFlow, m.output)
	return h.stream
}

// Handler parses the TCP data on a single stream into HTTP packets.
//
// Each time tcpassembly.StreamPool encounters a new TCP session, it will have
// the Factory create a new Handler to read the data on the stream.
type Handler struct {
	stream *tcpreader.ReaderStream
	out    chan<- string
	id     int
	src    string
	dst    string
}

// NewHandler creates a new Handler to decode a TCP stream.
//
// Using a Manager to create new Handlers should be used instead of this method.
func NewHandler(id int, net, tcp gopacket.Flow, out chan<- string) *Handler {
	s := tcpreader.NewReaderStream()
	h := &Handler{
		stream: &s,
		out:    out,
		id:     id,
		src:    fmt.Sprintf("%v:%v", net.Src(), tcp.Src()),
		dst:    fmt.Sprintf("%v:%v", net.Dst(), tcp.Dst()),
	}
	go h.Run()
	return h
}

// Run processes the data from the Handler's TCP stream.
func (h *Handler) Run() {
	streambuf := bufio.NewReader(h.stream)
	data, err := io.ReadAll(streambuf)
	if err != nil {
		fmt.Printf("[!] %s: failed to read from TCP stream: %v\n", h, err)
		return
	}
	datastr := string(data)
	if firstToken, _, ok := strings.Cut(datastr, " "); ok {
		if _, ok := httpTokens[firstToken]; ok {
			h.output(datastr)
		} else {
			h.output(fmt.Sprintf("[!] Non-HTTP token %q", firstToken))
		}
	} else {
		h.output("[!] Packet contained no spaces")
	}
}

func (h *Handler) output(data string) {
	b := new(bytes.Buffer)
	quick.Highlight(b, data, "http", "terminal16", "base16-snazzy")
	lines := strings.Split(b.String(), "\n")
	for i, l := range lines {
		lines[i] = "\x1b[0m│ " + l
	}

	buf := new(strings.Builder)
	fmt.Fprintln(buf, "╭───────────────────────────────────────────────────────────────────────────────")
	fmt.Fprintf(buf, "│ stream: %d\n", h.id)
	fmt.Fprintf(buf, "│ source: %s\n", h.src)
	fmt.Fprintf(buf, "│ dest:   %s\n", h.dst)
	fmt.Fprintln(buf, "├───────────────────────────────────────────────────────────────────────────────")
	fmt.Fprintln(buf, strings.Join(lines, "\n"))
	fmt.Fprintln(buf, "╰───────────────────────────────────────────────────────────────────────────────")
	h.out <- buf.String()
}

func (h *Handler) String() string {
	return fmt.Sprintf("stream %d %s 🡒 %s", h.id, h.src, h.dst)
}
