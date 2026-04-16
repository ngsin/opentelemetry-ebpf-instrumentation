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

// testREDMetricsCppHTTPClient verifies that the C++ ptrace-injected agent
// correctly instruments libcurl HTTP client calls and exports both
// Prometheus metrics and Jaeger traces.
func testREDMetricsCppHTTPClient(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}

	// The cppsvc makes periodic GET requests to cpphttpsvc:8080/greeting.
	// After C++ agent injection, we expect http_client_request_duration_seconds
	// metrics to appear in Prometheus.

	// 1. Verify HTTP client request duration metric exists
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`http_client_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="cppsvc"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		if len(results) > 0 {
			val := totalPromCount(ct, results)
			assert.LessOrEqual(ct, 1, val)
		}
	}, testTimeout, 100*time.Millisecond)

	// 2. Verify HTTP client request body size metric
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`http_client_request_body_size_bytes_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="cppsvc"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
	}, testTimeout, 100*time.Millisecond)

	// 3. Verify traces are exported to Jaeger
	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=cppsvc")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)})
		require.GreaterOrEqual(ct, len(traces), 1)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	// 4. Verify span attributes
	// OBI normalizes the operation name to "METHOD path" format.
	spans := trace.FindByOperationName("GET /greeting", "client")
	require.GreaterOrEqual(t, len(spans), 1)
	span := spans[0]

	sd := span.Diff(
		jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "client"},
	)
	assert.Empty(t, sd, sd.String())
}

// testREDMetricsCppHTTPSClient verifies that the C++ ptrace-injected agent
// correctly instruments libcurl HTTPS client calls (via SSL) and exports both
// Prometheus metrics and Jaeger traces.
func testREDMetricsCppHTTPSClient(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}

	// The cppsvctls makes periodic HTTPS GET requests to cpphttpssvc:8443/greeting.
	// After C++ agent injection, we expect http_client_request_duration_seconds
	// metrics to appear in Prometheus.

	// 1. Verify HTTPS client request duration metric exists
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`http_client_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="integration-test",` +
			`service_name="cppsvctls"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		if len(results) > 0 {
			val := totalPromCount(ct, results)
			assert.LessOrEqual(ct, 1, val)
		}
	}, testTimeout, 100*time.Millisecond)

	// 2. Verify traces are exported to Jaeger
	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=cppsvctls")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)})
		require.GreaterOrEqual(ct, len(traces), 1)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	// 3. Verify span attributes
	// OBI normalizes the operation name to "METHOD path" format.
	spans := trace.FindByOperationName("GET /greeting", "client")
	require.GreaterOrEqual(t, len(spans), 1)
	span := spans[0]

	sd := span.Diff(
		jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "client"},
	)
	assert.Empty(t, sd, sd.String())
}

// testREDMetricsCppHTTPSServer verifies that OBI instruments cpphttpssvc
// (cpp-httplib HTTPS server) via GOT hooking of SSL_read/SSL_write and produces
// HTTPS server spans with correct attributes.
func testREDMetricsCppHTTPSServer(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}

	// 1. Verify HTTPS server-side metrics from cpphttpssvc
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`url_path="/greeting",` +
			`service_name="cpphttpssvc"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		if len(results) > 0 {
			val := totalPromCount(ct, results)
			assert.LessOrEqual(ct, 1, val)
		}
	}, testTimeout, 100*time.Millisecond)

	// 2. Verify HTTPS server-side traces in Jaeger
	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=cpphttpssvc")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)})
		require.GreaterOrEqual(ct, len(traces), 1)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	// 3. Verify HTTPS server span attributes
	spans := trace.FindByOperationName("GET /greeting", "server")
	require.GreaterOrEqual(t, len(spans), 1)
	span := spans[0]

	sd := span.Diff(
		jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
	)
	assert.Empty(t, sd, sd.String())
}

// testREDMetricsCppHTTPServer verifies that OBI instruments the cpphttpsvc
// (cpp-httplib HTTP server) via GOT hooking of accept4/recv/send and produces
// HTTP server spans with correct attributes.
func testREDMetricsCppHTTPServer(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}

	// 1. Verify server-side metrics from cpphttpsvc receiving requests from cppsvc
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`url_path="/greeting",` +
			`service_name="cpphttpsvc"}`)
		require.NoError(ct, err)
		enoughPromResults(ct, results)
		if len(results) > 0 {
			val := totalPromCount(ct, results)
			assert.LessOrEqual(ct, 1, val)
		}
	}, testTimeout, 100*time.Millisecond)

	// 2. Verify server-side traces in Jaeger
	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=cpphttpsvc")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)})
		require.GreaterOrEqual(ct, len(traces), 1)
		trace = traces[0]
	}, testTimeout, 100*time.Millisecond)

	// 3. Verify server span attributes
	spans := trace.FindByOperationName("GET /greeting", "server")
	require.GreaterOrEqual(t, len(spans), 1)
	span := spans[0]

	sd := span.Diff(
		jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
	)
	assert.Empty(t, sd, sd.String())
}
