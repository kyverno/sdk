package imagedataloader

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"testing"

	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testMaxSize = int64(1 << 20)

// compressedBlob is a minimal gcr compressed layer backed by a fixed byte slice.
type compressedBlob struct {
	blob   []byte
	closed *bool
}

func (c compressedBlob) Compressed() (io.ReadCloser, error) {
	return readCloser{Reader: bytes.NewReader(c.blob), closed: c.closed}, nil
}
func (c compressedBlob) Size() (int64, error) { return int64(len(c.blob)), nil }
func (c compressedBlob) MediaType() (types.MediaType, error) {
	return types.DockerLayer, nil
}

func (c compressedBlob) Digest() (gcrv1.Hash, error) {
	h, _, err := gcrv1.SHA256(bytes.NewReader(c.blob))
	return h, err
}

type readCloser struct {
	io.Reader
	closed *bool
}

func (r readCloser) Close() error {
	if r.closed != nil {
		*r.closed = true
	}
	return nil
}

func layerFrom(t *testing.T, blob []byte, closed *bool) gcrv1.Layer {
	t.Helper()
	l, err := partial.CompressedToLayer(compressedBlob{blob: blob, closed: closed})
	require.NoError(t, err)
	return l
}

func gzipBytes(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(bytes.Repeat([]byte("A"), n))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func zstdBytes(t *testing.T, n int, window int) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf, zstd.WithWindowSize(window))
	require.NoError(t, err)
	_, err = enc.Write(bytes.Repeat([]byte("A"), n))
	require.NoError(t, err)
	require.NoError(t, enc.Close())
	return buf.Bytes()
}

func TestReadLayerLimited_GzipWithinLimit(t *testing.T) {
	b, err := readLayerLimited(layerFrom(t, gzipBytes(t, 1024), nil), testMaxSize)
	require.NoError(t, err)
	assert.Len(t, b, 1024)
}

// A small gzip blob that expands past the cap must error, not truncate.
func TestReadLayerLimited_GzipOutputTooLarge(t *testing.T) {
	b, err := readLayerLimited(layerFrom(t, gzipBytes(t, int(testMaxSize)+1), nil), testMaxSize)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uncompressed layer size exceeds")
	assert.Nil(t, b)
}

// An over-window zstd frame must be refused before the decoder allocates its window.
func TestReadLayerLimited_ZstdWindowInflation(t *testing.T) {
	frame := []byte{0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x98, 0x01, 0x00, 0x00}
	_, err := readLayerLimited(layerFrom(t, frame, nil), testMaxSize)
	require.Error(t, err)
	assert.True(t, errors.Is(err, zstd.ErrWindowSizeExceeded), "got %v", err)
}

func TestReadLayerLimited_ZstdOutputTooLarge(t *testing.T) {
	blob := zstdBytes(t, int(testMaxSize)+1, 1<<16)
	_, err := readLayerLimited(layerFrom(t, blob, nil), testMaxSize)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uncompressed layer size exceeds")
}

func TestReadLayerLimited_CompressedTooLarge(t *testing.T) {
	_, err := readLayerLimited(layerFrom(t, bytes.Repeat([]byte("x"), int(testMaxSize)+1), nil), testMaxSize)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "layer size")
}

func TestReadLayerLimited_ClosesReader(t *testing.T) {
	for name, blob := range map[string][]byte{
		"within limit": gzipBytes(t, 512),
		"oversized":    gzipBytes(t, int(testMaxSize)+1),
	} {
		t.Run(name, func(t *testing.T) {
			closed := false
			_, _ = readLayerLimited(layerFrom(t, blob, &closed), testMaxSize)
			assert.True(t, closed, "compressed reader was not closed")
		})
	}
}

func TestPayloadLimit_SetChangesButNeverDisables(t *testing.T) {
	restore := PayloadLimit()
	t.Cleanup(func() { SetPayloadLimit(restore) })

	assert.Equal(t, defaultPayloadLimit, PayloadLimit())

	// A larger positive value raises the bound.
	SetPayloadLimit(50 * 1000 * 1000)
	assert.Equal(t, int64(50*1000*1000), PayloadLimit())

	// A smaller positive value tightens it: the bound can move in either
	// direction, which is the documented contract.
	SetPayloadLimit(1 * 1000 * 1000)
	assert.Equal(t, int64(1*1000*1000), PayloadLimit())

	// A non-positive value is how a caller spells "leave the current bound
	// alone"; the bound can never be disabled.
	SetPayloadLimit(0)
	assert.Equal(t, int64(1*1000*1000), PayloadLimit())
	SetPayloadLimit(-1)
	assert.Equal(t, int64(1*1000*1000), PayloadLimit())
}

// A payload between the default and a raised limit must become readable, which is
// the large SBOM attestation case the compile-time constant refused outright.
func TestReadLayerLimited_RaisedLimitAcceptsLargerPayload(t *testing.T) {
	const payload = 12 * 1000 * 1000
	blob := gzipBytes(t, payload)

	_, err := readLayerLimited(layerFrom(t, blob, nil), defaultPayloadLimit)
	require.Error(t, err, "the default must still refuse it")

	b, err := readLayerLimited(layerFrom(t, blob, nil), 20*1000*1000)
	require.NoError(t, err)
	assert.Len(t, b, payload)
}
