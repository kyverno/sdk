package imagedataloader

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func declaredOrReal(real, override int64) int64 {
	if override != 0 {
		return override
	}
	return real
}

type rawManifestTaggable struct{ raw []byte }

func (r rawManifestTaggable) RawManifest() ([]byte, error) { return r.raw, nil }
func (r rawManifestTaggable) MediaType() (types.MediaType, error) {
	return types.DockerManifestSchema2, nil
}

// pushImageWithConfig publishes an image whose config blob is configSize bytes and returns its tagged ref.
func pushImageWithConfig(t *testing.T, configSize int) string {
	t.Helper()
	return pushImageWithDeclaredConfigSize(t, configSize, 0)
}

// pushImageWithDeclaredConfigSize publishes an image whose config blob is configSize
// bytes while its manifest declares declaredSize, or the real size when that is 0.
func pushImageWithDeclaredConfigSize(t *testing.T, configSize int, declaredSize int64) string {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)

	repo, err := name.NewRepository(strings.TrimPrefix(srv.URL, "http://") + "/test/cfg")
	require.NoError(t, err)

	cfg, err := json.Marshal(map[string]any{
		"architecture": "amd64",
		"os":           "linux",
		"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{}},
		"padding":      string(bytes.Repeat([]byte("A"), configSize)),
	})
	require.NoError(t, err)

	cfgLayer := static.NewLayer(cfg, types.DockerConfigJSON)
	require.NoError(t, remote.WriteLayer(repo, cfgLayer))
	cfgDigest, err := cfgLayer.Digest()
	require.NoError(t, err)
	cfgSize, err := cfgLayer.Size()
	require.NoError(t, err)

	raw, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     string(types.DockerManifestSchema2),
		"config": map[string]any{
			"mediaType": string(types.DockerConfigJSON),
			"digest":    cfgDigest.String(),
			"size":      declaredOrReal(cfgSize, declaredSize),
		},
		"layers": []any{},
	})
	require.NoError(t, err)

	tag := repo.Tag("latest")
	require.NoError(t, remote.Put(tag, rawManifestTaggable{raw: raw}))
	return tag.Name()
}

func TestFetchImageData_RejectsOversizedConfig(t *testing.T) {
	ref := pushImageWithConfig(t, int(defaultPayloadLimit)+1)
	idf, err := New(nil, nil, nil)
	require.NoError(t, err)

	_, err = idf.FetchImageData(context.Background(), ref, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config size")
	assert.Contains(t, err.Error(), "exceeds")
}

// A declared size of -1 is go-containerregistry's "unknown", which switches off its
// own bound on the body, so the whole blob is buffered and the digest only checked at
// EOF. A "> limit" check lets it through.
func TestFetchImageData_RejectsUnknownConfigSize(t *testing.T) {
	ref := pushImageWithDeclaredConfigSize(t, 4096, -1)
	idf, err := New(nil, nil, nil)
	require.NoError(t, err)

	_, err = idf.FetchImageData(context.Background(), ref, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid declared size")
}

// The config read has to follow SetPayloadLimit like the referrer read does.
func TestFetchImageData_ConfigHonoursConfiguredPayloadLimit(t *testing.T) {
	restore := PayloadLimit()
	t.Cleanup(func() { SetPayloadLimit(restore) })

	ref := pushImageWithConfig(t, int(defaultPayloadLimit)+1)
	idf, err := New(nil, nil, nil)
	require.NoError(t, err)

	_, err = idf.FetchImageData(context.Background(), ref, nil, nil)
	require.Error(t, err, "refused at the default limit")

	SetPayloadLimit(defaultPayloadLimit * 4)
	img, err := idf.FetchImageData(context.Background(), ref, nil, nil)
	require.NoError(t, err, "a raised limit must reach the config read")
	require.NotNil(t, img)
}

func TestFetchImageData_AcceptsNormalConfig(t *testing.T) {
	ref := pushImageWithConfig(t, 1024)
	idf, err := New(nil, nil, nil)
	require.NoError(t, err)

	img, err := idf.FetchImageData(context.Background(), ref, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, img)
}
