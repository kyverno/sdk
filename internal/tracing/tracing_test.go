package tracing

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

// recordingSpan reports itself as recording. Only IsRecording is ever called
// on it by the code under test, so the embedded nil interface is never reached.
type recordingSpan struct{ trace.Span }

func (recordingSpan) IsRecording() bool { return true }

func TestTransport_WrapsBaseInAnOtelTransport(t *testing.T) {
	base := http.DefaultTransport

	tr := Transport(base)

	require.NotNil(t, tr)
	assert.Implements(t, (*http.RoundTripper)(nil), tr)
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
