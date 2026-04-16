// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

// testCppRedisTraceCorrelation verifies that a C++ HTTP server span (from the
// C++ agent via GOT hooking of accept4/recv/send) and Redis client spans
// (from eBPF kprobe) are correlated under the same trace when a known traceID
// is injected via the traceparent HTTP header.
func testCppRedisTraceCorrelation(t *testing.T) {
	waitForCppRedisComponents(t, "http://localhost:8080/redis-ping")
	verifyCppRedisTrace(t, "http://localhost:8080/redis-ping", "cpphttpsvc")
}

// testCppRedisTraceCorrelationTLS verifies HTTPS trace instrumentation.
//
// NOTE: cpp-httplib performs byte-at-a-time SSL_read when parsing HTTP headers.
// The eBPF SSL_read accumulation buffer enables protocol detection (is_http),
// but the full HTTP request line and headers cannot be read from the tiny
// user-space buffer. As a result, the eBPF layer generates HTTP server spans
// with potentially garbled request data, and traceparent extraction from HTTP
// headers is not possible for byte-at-a-time TLS readers.
//
// Instead of full trace correlation, we verify that:
//   - Redis client spans (SET/GET) are correctly generated via kprobe on the
//     plain TCP connection from cpphttpssvc to Redis
//   - The HTTPS client span from cppsvctls is produced via SSL uprobe
func testCppRedisTraceCorrelationTLS(t *testing.T) {
	waitForCppRedisComponents(t, "https://localhost:8443/redis-ping")
	verifyCppRedisHTTPSSpans(t)
}

// verifyCppRedisTrace is the shared verification logic for both HTTP and HTTPS.
//
// Test flow:
//  1. Generate a known traceID and send an HTTP(S) request with that
//     traceparent to the target service's /redis-ping endpoint
//  2. The server handles the request (C++ agent creates HTTP server span)
//     and calls Redis SET + GET via hiredis (eBPF creates Redis client spans)
//  3. Verify in Jaeger that the HTTP server span and Redis spans share the
//     same traceID
func verifyCppRedisTrace(t *testing.T, url, serviceName string) {
	// 1. Generate a known traceID and parentID
	traceID := createTraceID()
	parentID := createParentID()
	traceparent := createTraceparent(traceID, parentID)

	// 2. Send multiple requests with the known traceparent to ensure traces
	// are generated and flushed to Jaeger.
	for range 4 {
		doHTTPGetWithTraceparent(t, url, 200, traceparent)
	}

	// 3. Wait for the HTTP server span to appear in Jaeger with our traceID
	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=" + serviceName)
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))

		// Find a trace that contains our known traceID
		found := false
		for _, tr := range tq.Data {
			if tr.TraceID == traceID {
				trace = tr
				found = true
				break
			}
		}
		require.True(ct, found, "trace with ID %s not found in Jaeger for service %s", traceID, serviceName)

		// The trace should have at least 2 spans:
		// 1 HTTP server span + at least 1 Redis span
		require.GreaterOrEqual(ct, len(trace.Spans), 2,
			"expected at least 2 spans (HTTP server + Redis), got %d", len(trace.Spans))
	}, testTimeout, 100*time.Millisecond)

	// 4. Verify the HTTP server span exists and has correct attributes
	serverSpans := trace.FindByOperationName("GET /redis-ping", "server")
	require.GreaterOrEqual(t, len(serverSpans), 1,
		"no HTTP server span found for GET /redis-ping in service %s", serviceName)
	serverSpan := serverSpans[0]

	sd := serverSpan.Diff(
		jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
	)
	assert.Empty(t, sd, "HTTP server span attribute mismatch: %s", sd.String())

	// 5. Verify Redis spans exist in the same trace
	// Find spans with db.system.name=redis
	var redisSpans []jaeger.Span
	for _, span := range trace.Spans {
		tag, found := jaeger.FindIn(span.Tags, "db.system.name")
		if found && tag.Value == "redis" {
			redisSpans = append(redisSpans, span)
		}
	}
	require.GreaterOrEqual(t, len(redisSpans), 1,
		"no Redis spans found in trace %s", traceID)

	// 6. Verify all Redis spans share the same traceID as the HTTP server span
	for _, rs := range redisSpans {
		assert.Equal(t, traceID, rs.TraceID,
			"Redis span traceID mismatch: expected %s, got %s", traceID, rs.TraceID)
	}

	// 7. Verify at least one SET and one GET Redis span exist
	foundSET := false
	foundGET := false
	for _, rs := range redisSpans {
		if rs.OperationName == "SET" {
			foundSET = true
			sd := rs.Diff(
				jaeger.Tag{Key: "db.system.name", Type: "string", Value: "redis"},
				jaeger.Tag{Key: "span.kind", Type: "string", Value: "client"},
			)
			assert.Empty(t, sd, "Redis SET span attribute mismatch: %s", sd.String())
		}
		if rs.OperationName == "GET" {
			foundGET = true
			sd := rs.Diff(
				jaeger.Tag{Key: "db.system.name", Type: "string", Value: "redis"},
				jaeger.Tag{Key: "span.kind", Type: "string", Value: "client"},
			)
			assert.Empty(t, sd, "Redis GET span attribute mismatch: %s", sd.String())
		}
	}
	assert.True(t, foundSET, "no Redis SET span found in trace %s", traceID)
	assert.True(t, foundGET, "no Redis GET span found in trace %s", traceID)
}

// verifyCppRedisHTTPSSpans verifies that HTTPS traffic to cpphttpssvc produces
// Redis client spans and that the HTTPS client (cppsvctls) produces client spans.
//
// Due to cpp-httplib's byte-at-a-time SSL_read pattern, the eBPF HTTP parser
// cannot generate HTTP server spans for HTTPS. So we verify the components that
// DO work: Redis sub-spans from cpphttpssvc, and HTTPS client spans from cppsvctls.
func verifyCppRedisHTTPSSpans(t *testing.T) {
	// 1. Verify cpphttpssvc produces Redis spans (SET and GET)
	var redisTrace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=cpphttpssvc")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))

		// Find a trace with Redis spans
		found := false
		for _, tr := range tq.Data {
			for _, span := range tr.Spans {
				tag, ok := jaeger.FindIn(span.Tags, "db.system.name")
				if ok && tag.Value == "redis" {
					redisTrace = tr
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		require.True(ct, found, "no trace with Redis spans found for cpphttpssvc")
	}, testTimeout, 100*time.Millisecond)

	// 2. Verify Redis SET and GET spans exist with correct attributes
	foundSET := false
	foundGET := false
	for _, span := range redisTrace.Spans {
		tag, ok := jaeger.FindIn(span.Tags, "db.system.name")
		if !ok || tag.Value != "redis" {
			continue
		}
		if span.OperationName == "SET" {
			foundSET = true
			sd := span.Diff(
				jaeger.Tag{Key: "db.system.name", Type: "string", Value: "redis"},
				jaeger.Tag{Key: "span.kind", Type: "string", Value: "client"},
			)
			assert.Empty(t, sd, "Redis SET span attribute mismatch: %s", sd.String())
		}
		if span.OperationName == "GET" {
			foundGET = true
			sd := span.Diff(
				jaeger.Tag{Key: "db.system.name", Type: "string", Value: "redis"},
				jaeger.Tag{Key: "span.kind", Type: "string", Value: "client"},
			)
			assert.Empty(t, sd, "Redis GET span attribute mismatch: %s", sd.String())
		}
	}
	assert.True(t, foundSET, "no Redis SET span found for cpphttpssvc")
	assert.True(t, foundGET, "no Redis GET span found for cpphttpssvc")

	// 3. Verify cppsvctls produces HTTPS client spans
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=cppsvctls")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		require.NotEmpty(ct, tq.Data, "no traces found for cppsvctls")

		// Find an HTTPS client span
		found := false
		for _, tr := range tq.Data {
			for _, span := range tr.Spans {
				kindTag, ok := jaeger.FindIn(span.Tags, "span.kind")
				if ok && kindTag.Value == "client" {
					schemeTag, ok := jaeger.FindIn(span.Tags, "url.scheme")
					if ok && schemeTag.Value == "https" {
						found = true
						break
					}
				}
			}
			if found {
				break
			}
		}
		require.True(ct, found, "no HTTPS client span found for cppsvctls")
	}, testTimeout, 100*time.Millisecond)
}

// waitForCppRedisComponents waits until the target endpoint is reachable
// and Redis metrics appear in Prometheus, indicating OBI has started
// instrumenting the services.
func waitForCppRedisComponents(t *testing.T, url string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Verify the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url, nil)
		require.NoError(ct, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, r.StatusCode)

		// Verify that Redis metrics are being reported by OBI
		results, err := pq.Query(`db_client_operation_duration_seconds_count{db_system_name="redis"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, 2*time.Minute, time.Second)
}
