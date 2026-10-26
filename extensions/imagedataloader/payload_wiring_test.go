package imagedataloader

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pushReferrerLayer publishes a single-layer image whose one layer decompresses
// to payload bytes, and returns the repo tag plus the image digest.
func pushReferrerLayer(t *testing.T, payload int) (name.Reference, gcrv1.Hash) {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)

	repo, err := name.NewRepository(strings.TrimPrefix(srv.URL, "http://") + "/test/ref")
	require.NoError(t, err)

	layer := static.NewLayer(gzipBytes(t, payload), types.MediaType("application/vnd.oci.image.layer.v1.tar+gzip"))
	img, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)

	tag := repo.Tag("ref")
	require.NoError(t, remote.Write(tag, img))
	dig, err := img.Digest()
	require.NoError(t, err)
	return tag, dig
}

// FetchReferrerData must honour SetPayloadLimit on the production fetch path, not
// only when readLayerLimited is handed a literal limit. A payload between the
// default and a raised limit is refused at the default and read once raised.
// Reverting the call site to a fixed limit fails this test.
func TestFetchReferrerData_HonoursConfiguredPayloadLimit(t *testing.T) {
	const payload = 12 * 1000 * 1000 // between the 10 MB default and the 20 MB raise

	restore := PayloadLimit()
	t.Cleanup(func() { SetPayloadLimit(restore) })

	ref, dig := pushReferrerLayer(t, payload)
	desc := gcrv1.Descriptor{Digest: dig}

	// At the default limit the production path refuses the payload.
	atDefault := &ImageData{nameRef: ref, referrersData: make(map[string]referrerData)}
	_, _, err := atDefault.FetchReferrerData(desc)
	require.Error(t, err, "the default limit must refuse a 12 MB payload through FetchReferrerData")
	assert.Contains(t, err.Error(), "exceeds")

	// Raising the limit makes the same production path read it.
	SetPayloadLimit(20 * 1000 * 1000)
	raised := &ImageData{nameRef: ref, referrersData: make(map[string]referrerData)}
	b, _, err := raised.FetchReferrerData(desc)
	require.NoError(t, err, "a raised limit must let FetchReferrerData read the payload")
	assert.Len(t, b, payload)
}
