package tracing

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// recordingSpan reports itself as recording, which is all the request filter
// looks at. Every other method is a no-op from the embedded span.
type recordingSpan struct{ noop.Span }

func (recordingSpan) IsRecording() bool { return true }

// spanRecorder is a tracer provider that remembers the name of every span the
// transport starts, so a test can see what would have been traced.
type spanRecorder struct {
	noop.TracerProvider
	names []string
}

func (r *spanRecorder) Tracer(string, ...trace.TracerOption) trace.Tracer {
	return recordingTracer{rec: r}
}

type recordingTracer struct {
	noop.Tracer
	rec *spanRecorder
}

func (t recordingTracer) Start(ctx context.Context, name string, _ ...trace.SpanStartOption) (context.Context, trace.Span) {
	t.rec.names = append(t.rec.names, name)
	return ctx, noop.Span{}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// countingBase is a stand-in registry: it answers 200 and counts the requests it saw.
func countingBase(calls *int) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		*calls++
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: r}, nil
	})
}

func roundTrip(t *testing.T, tr http.RoundTripper, req *http.Request) *http.Response {
	t.Helper()
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// The span is named after the method and path only. The query string must stay
// out of it, since registry URLs can carry tokens there.
func TestTransport_NamesSpanAfterMethodAndPathAndCallsBase(t *testing.T) {
	rec := &spanRecorder{}
	calls := 0
	tr := Transport(countingBase(&calls), otelhttp.WithTracerProvider(rec))

	req, err := http.NewRequest(http.MethodGet, "https://ghcr.io/v2/kyverno/kyverno/manifests/latest?token=secret", nil)
	require.NoError(t, err)
	resp := roundTrip(t, tr, req)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 1, calls, "the wrapped transport must still perform the request")
	assert.Equal(t, []string{"HTTP GET /v2/kyverno/kyverno/manifests/latest"}, rec.names)
}

// This is how the registry client builds its transport: traced only when the
// caller is already inside a trace. Outside one, the request must still go
// through, just without a span.
func TestTransport_WithFilter_SkipsSpanOutsideATraceButStillCallsBase(t *testing.T) {
	rec := &spanRecorder{}
	calls := 0
	tr := Transport(countingBase(&calls),
		otelhttp.WithTracerProvider(rec),
		otelhttp.WithFilter(RequestFilterIsInSpan),
	)

	req, err := http.NewRequest(http.MethodGet, "https://ghcr.io/v2/", nil)
	require.NoError(t, err)
	roundTrip(t, tr, req)

	assert.Equal(t, 1, calls, "an untraced request must still reach the registry")
	assert.Empty(t, rec.names, "no span should be started outside a trace")
}

func TestTransport_WithFilter_TracesInsideATrace(t *testing.T) {
	rec := &spanRecorder{}
	calls := 0
	tr := Transport(countingBase(&calls),
		otelhttp.WithTracerProvider(rec),
		otelhttp.WithFilter(RequestFilterIsInSpan),
	)

	req, err := http.NewRequest(http.MethodGet, "https://ghcr.io/v2/", nil)
	require.NoError(t, err)
	req = req.WithContext(trace.ContextWithSpan(req.Context(), recordingSpan{}))
	roundTrip(t, tr, req)

	assert.Equal(t, 1, calls)
	assert.Equal(t, []string{"HTTP GET /v2/"}, rec.names)
}

// The filter is what keeps registry calls out of the traces when nothing is
// being traced. Without a recording span in the request context it must say no.
func TestRequestFilterIsInSpan_FalseWithoutRecordingSpan(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://ghcr.io/v2/", nil)
	require.NoError(t, err)

	assert.False(t, RequestFilterIsInSpan(req))
}

// With a recording span on the request context the call should be traced.
func TestRequestFilterIsInSpan_TrueWithRecordingSpan(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://ghcr.io/v2/", nil)
	require.NoError(t, err)
	req = req.WithContext(trace.ContextWithSpan(context.Background(), recordingSpan{}))

	assert.True(t, RequestFilterIsInSpan(req))
}
