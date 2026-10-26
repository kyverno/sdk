// Package tracing provides the small amount of OpenTelemetry HTTP glue the SDK
// needs for its registry client.
//
// These helpers were previously imported from github.com/kyverno/kyverno/pkg/tracing,
// which made the SDK depend on the Kyverno controller module. They are kept here
// so the SDK stays standalone.
package tracing

import (
	"context"
	"fmt"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
)

var defaultSpanFormatter = otelhttp.WithSpanNameFormatter(
	func(_ string, request *http.Request) string {
		return fmt.Sprintf("HTTP %s %s", request.Method, request.URL.Path)
	},
)

// IsInSpan reports whether ctx carries a span that is currently recording.
func IsInSpan(ctx context.Context) bool {
	span := trace.SpanFromContext(ctx)
	return span.IsRecording()
}

// RequestFilterIsInSpan reports whether a request should be traced, which it
// should only be when its context already carries a recording span.
func RequestFilterIsInSpan(request *http.Request) bool {
	return IsInSpan(request.Context())
}

// Transport wraps base in an OpenTelemetry transport that names spans after the
// request method and path.
func Transport(base http.RoundTripper, opts ...otelhttp.Option) *otelhttp.Transport {
	o := make([]otelhttp.Option, 0, 1+len(opts))
	o = append(o, defaultSpanFormatter)
	o = append(o, opts...)
	return otelhttp.NewTransport(base, o...)
}
