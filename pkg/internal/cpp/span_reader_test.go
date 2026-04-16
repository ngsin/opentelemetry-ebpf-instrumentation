// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cpp

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestSpanReader_ReadOneSpan(t *testing.T) {
	// Create a connected pair of Unix sockets
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	defer listener.Close()

	// Connect client
	client, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer client.Close()

	// Accept server side
	server, err := listener.Accept()
	require.NoError(t, err)
	defer server.Close()

	// Build a test span event
	wire := spanEventWire{
		EventType:   3, // EventTypeHTTPClient
		Flags:       0,
		Status:      200,
		MethodLen:   3,
		URLLen:      19,
		StartTimeNs: 1000000000,
		EndTimeNs:   1100000000,
		TraceID:     [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:      [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
	}

	method := "GET"
	url := "http://example.com/"

	// Write to client
	err = binary.Write(client, binary.LittleEndian, wire)
	require.NoError(t, err)
	_, err = client.Write([]byte(method))
	require.NoError(t, err)
	_, err = client.Write([]byte(url))
	require.NoError(t, err)

	// Read from server
	sr := &SpanReader{hostPID: 42, log: slog.Default().With("component", "test")}
	span, err := sr.readOneSpan(server)
	require.NoError(t, err)

	assert.Equal(t, request.EventTypeHTTPClient, span.Type)
	assert.Equal(t, 200, span.Status)
	assert.Equal(t, "GET", span.Method)
	assert.Equal(t, "http://example.com/", span.Path)
	assert.Equal(t, int64(1000000000), span.Start)
	assert.Equal(t, int64(1100000000), span.End)
	assert.Equal(t, [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, [16]byte(span.TraceID))
	assert.Equal(t, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, [8]byte(span.SpanID))
	assert.Equal(t, app.PID(42), span.Pid.HostPID)
}

func TestSpanReader_StartAndClose(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "tmp", ".obi-99.sock")

	// Create SpanReader manually (bypassing NewSpanReader which uses /proc paths)
	err := os.MkdirAll(filepath.Dir(sockPath), 0755)
	require.NoError(t, err)

	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)

	sr := &SpanReader{
		nsPID:      99,
		hostPID:    99,
		socketPath: sockPath,
		listener:   listener,
		log:        slog.Default().With("component", "test"),
	}

	output := make(chan []request.Span, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sr.Start(ctx, output)

	// Connect a client and send a span
	client, err := net.Dial("unix", sockPath)
	require.NoError(t, err)

	wire := spanEventWire{
		EventType:   3,
		Status:      404,
		MethodLen:   4,
		URLLen:      11,
		StartTimeNs: 2000000000,
		EndTimeNs:   2200000000,
	}
	err = binary.Write(client, binary.LittleEndian, wire)
	require.NoError(t, err)
	_, err = client.Write([]byte("POST"))
	require.NoError(t, err)
	_, err = client.Write([]byte("/api/v1/foo"))
	require.NoError(t, err)
	client.Close()

	// Read the span from output
	select {
	case spans := <-output:
		require.Len(t, spans, 1)
		assert.Equal(t, request.EventTypeHTTPClient, spans[0].Type)
		assert.Equal(t, 404, spans[0].Status)
		assert.Equal(t, "POST", spans[0].Method)
		assert.Equal(t, "/api/v1/foo", spans[0].Path)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for span")
	}

	sr.Close()

	// Socket file should be cleaned up
	_, err = os.Stat(sockPath)
	assert.True(t, os.IsNotExist(err))
}

func TestSpanReader_ReadOneSpan_HTTPServer(t *testing.T) {
	// Test reading an HTTP server span (event_type=1, OBI_EVENT_HTTP_SERVER)
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	defer listener.Close()

	client, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer client.Close()

	server, err := listener.Accept()
	require.NoError(t, err)
	defer server.Close()

	// EventType=1 corresponds to EventTypeHTTP (server-side HTTP)
	wire := spanEventWire{
		EventType:   1, // OBI_EVENT_HTTP_SERVER → EventTypeHTTP
		Flags:       0,
		Status:      200,
		MethodLen:   3,
		URLLen:      9,
		StartTimeNs: 5000000000,
		EndTimeNs:   5050000000,
	}

	method := "GET"
	url := "/api/test"

	err = binary.Write(client, binary.LittleEndian, wire)
	require.NoError(t, err)
	_, err = client.Write([]byte(method))
	require.NoError(t, err)
	_, err = client.Write([]byte(url))
	require.NoError(t, err)

	sr := &SpanReader{hostPID: 100, log: slog.Default().With("component", "test")}
	span, err := sr.readOneSpan(server)
	require.NoError(t, err)

	assert.Equal(t, request.EventTypeHTTP, span.Type, "HTTP server event type should be EventTypeHTTP")
	assert.Equal(t, 200, span.Status)
	assert.Equal(t, "GET", span.Method)
	assert.Equal(t, "/api/test", span.Path)
	assert.Equal(t, int64(5000000000), span.Start)
	assert.Equal(t, int64(5050000000), span.End)
}

func TestHostSocketPath(t *testing.T) {
	path := HostSocketPath(12345)
	assert.Equal(t, "/proc/12345/root/tmp/.obi-12345.sock", path)
}
