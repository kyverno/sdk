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

type rawManifestTaggable struct{ raw []byte }

func (r rawManifestTaggable) RawManifest() ([]byte, error) { return r.raw, nil }
func (r rawManifestTaggable) MediaType() (types.MediaType, error) {
	return types.DockerManifestSchema2, nil
}

// pushImageWithConfig publishes an image whose config blob is configSize bytes and returns its tagged ref.
func pushImageWithConfig(t *testing.T, configSize int) string {
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
			"size":      cfgSize,
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

func TestFetchImageData_AcceptsNormalConfig(t *testing.T) {
	ref := pushImageWithConfig(t, 1024)
	idf, err := New(nil, nil, nil)
	require.NoError(t, err)

	img, err := idf.FetchImageData(context.Background(), ref, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, img)
}
