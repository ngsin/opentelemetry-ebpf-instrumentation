// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cpp // import "go.opentelemetry.io/obi/pkg/internal/cpp"

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

// spanEventWire represents the fixed-size header of the wire protocol.
// Matches struct obi_span_event in span.h.
type spanEventWire struct {
	EventType    uint8
	Flags        uint8
	Status       uint16
	MethodLen    uint32
	URLLen       uint32
	StartTimeNs  uint64
	EndTimeNs    uint64
	TraceID      [16]byte
	SpanID       [8]byte
	ParentSpanID [8]byte
}

// SpanReader listens on a Unix domain socket for span events sent by agent.so.
// It parses the binary protocol and converts events into request.Span instances.
type SpanReader struct {
	log        *slog.Logger
	nsPID      app.PID    // namespace PID (for socket path)
	hostPID    app.PID    // host PID (for span attribution)
	pidNS      uint32     // PID namespace inode
	service    svc.Attrs  // service attributes for span decoration
	socketPath string
	listener   net.Listener
	wg         sync.WaitGroup
	cancel     context.CancelFunc
}

// NewSpanReader creates a Unix domain socket listener for receiving spans
// from the injected agent.so in the target process.
// nsPID is the namespace PID (what the process sees via getpid(), used for socket path).
// hostPID is the host PID (used for span PID attribution in the pipeline).
// pidNS is the PID namespace inode.
// service is the service attributes for decorating spans.
func NewSpanReader(nsPID, hostPID app.PID, pidNS uint32, service svc.Attrs, rootDir string) (*SpanReader, error) {
	// Socket path visible from inside the container
	containerSocketPath := fmt.Sprintf("/tmp/.obi-%d.sock", nsPID)
	// Host-side path through /proc/<host_pid>/root/
	hostSocketPath := filepath.Join(rootDir, containerSocketPath)

	// Ensure the directory exists
	dir := filepath.Dir(hostSocketPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating socket directory %s: %w", dir, err)
	}

	// Remove stale socket if it exists
	os.Remove(hostSocketPath)

	listener, err := net.Listen("unix", hostSocketPath)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", hostSocketPath, err)
	}

	return &SpanReader{
		log:        slog.With("component", "cpp.SpanReader", "pid", hostPID),
		nsPID:      nsPID,
		hostPID:    hostPID,
		pidNS:      pidNS,
		service:    service,
		socketPath: hostSocketPath,
		listener:   listener,
	}, nil
}

// SocketPathInContainer returns the socket path as seen from inside the container.
func (sr *SpanReader) SocketPathInContainer() string {
	return fmt.Sprintf("/tmp/.obi-%d.sock", sr.nsPID)
}

// Start begins accepting connections and reading span events.
// Parsed spans are sent to the output channel.
func (sr *SpanReader) Start(ctx context.Context, output chan<- []request.Span) {
	ctx, sr.cancel = context.WithCancel(ctx)

	sr.wg.Add(1)
	go func() {
		defer sr.wg.Done()
		sr.acceptLoop(ctx, output)
	}()
}

// Close shuts down the listener and waits for goroutines to finish.
func (sr *SpanReader) Close() {
	if sr.cancel != nil {
		sr.cancel()
	}
	if sr.listener != nil {
		sr.listener.Close()
	}
	sr.wg.Wait()

	// Cleanup socket file
	os.Remove(sr.socketPath)
	sr.log.Debug("span reader closed")
}

func (sr *SpanReader) acceptLoop(ctx context.Context, output chan<- []request.Span) {
	for {
		conn, err := sr.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				sr.log.Warn("accept error", "error", err)
				return
			}
		}

		sr.wg.Add(1)
		go func() {
			defer sr.wg.Done()
			sr.readConnection(ctx, conn, output)
		}()
	}
}

func (sr *SpanReader) readConnection(ctx context.Context, conn net.Conn, output chan<- []request.Span) {
	defer conn.Close()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		span, err := sr.readOneSpan(conn)
		if err != nil {
			if err != io.EOF {
				sr.log.Debug("read error", "error", err)
			}
			return
		}

		// Send the span to the output pipeline
		select {
		case output <- []request.Span{span}:
		case <-ctx.Done():
			return
		}
	}
}

func (sr *SpanReader) readOneSpan(r io.Reader) (request.Span, error) {
	// Read fixed header
	var wire spanEventWire
	if err := binary.Read(r, binary.LittleEndian, &wire); err != nil {
		return request.Span{}, err
	}

	// Read variable-length method
	method := ""
	if wire.MethodLen > 0 {
		methodBuf := make([]byte, wire.MethodLen)
		if _, err := io.ReadFull(r, methodBuf); err != nil {
			return request.Span{}, fmt.Errorf("reading method: %w", err)
		}
		method = string(methodBuf)
	}

	// Read variable-length URL
	url := ""
	if wire.URLLen > 0 {
		urlBuf := make([]byte, wire.URLLen)
		if _, err := io.ReadFull(r, urlBuf); err != nil {
			return request.Span{}, fmt.Errorf("reading url: %w", err)
		}
		url = string(urlBuf)
	}

	// Convert to request.Span
	span := request.Span{
		Type:         request.EventType(wire.EventType),
		Flags:        wire.Flags,
		Method:       method,
		Path:         url,
		Status:       int(wire.Status),
		RequestStart: int64(wire.StartTimeNs),
		Start:        int64(wire.StartTimeNs),
		End:          int64(wire.EndTimeNs),
		Pid: request.PidInfo{
			HostPID:   sr.hostPID,
			UserPID:   sr.hostPID,
			Namespace: sr.pidNS,
		},
		Service: sr.service,
	}

	// Set trace context if present
	if wire.TraceID != [16]byte{} {
		span.TraceID = trace.TraceID(wire.TraceID)
	}
	if wire.SpanID != [8]byte{} {
		span.SpanID = trace.SpanID(wire.SpanID)
	}
	if wire.ParentSpanID != [8]byte{} {
		span.ParentSpanID = trace.SpanID(wire.ParentSpanID)
	}

	if sr.log != nil {
		sr.log.Debug("read span from agent",
			"type", span.Type,
			"method", span.Method,
			"path", span.Path,
			"status", span.Status,
			"rawStartNs", wire.StartTimeNs,
			"rawEndNs", wire.EndTimeNs,
		)
	}

	return span, nil
}

// HostSocketPath returns the host-side socket path for a given PID.
func HostSocketPath(pid app.PID) string {
	return filepath.Join("/proc", strconv.Itoa(int(pid)), "root", "tmp",
		fmt.Sprintf(".obi-%d.sock", pid))
}
