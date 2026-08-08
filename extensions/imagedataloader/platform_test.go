package imagedataloader

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func platformImage(t *testing.T, os, arch string) gcrv1.Image {
	t.Helper()

	img, err := random.Image(256, 1)
	require.NoError(t, err)

	cfg, err := img.ConfigFile()
	require.NoError(t, err)

	cfg = cfg.DeepCopy()
	cfg.OS = os
	cfg.Architecture = arch

	img, err = mutate.ConfigFile(img, cfg)
	require.NoError(t, err)

	return img
}

func platformChild(t *testing.T, os, arch string) mutate.IndexAddendum {
	t.Helper()

	return mutate.IndexAddendum{
		Add: platformImage(t, os, arch),
		Descriptor: gcrv1.Descriptor{
			Platform: &gcrv1.Platform{OS: os, Architecture: arch},
		},
	}
}

func startRegistry(t *testing.T) string {
	t.Helper()

	server := httptest.NewServer(registry.New())
	t.Cleanup(server.Close)

	parsed, err := url.Parse(server.URL)
	require.NoError(t, err)

	return parsed.Host
}

func TestFetchImageData_IndexPlatformSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		children []mutate.IndexAddendum
		wantArch string
		wantErr  string
	}{{
		name:     "single arm64 image is selected",
		children: []mutate.IndexAddendum{platformChild(t, "linux", "arm64")},
		wantArch: "arm64",
	}, {
		name: "buildkit attestation does not make the index ambiguous",
		children: []mutate.IndexAddendum{
			platformChild(t, "linux", "arm64"),
			platformChild(t, "unknown", "unknown"),
		},
		wantArch: "arm64",
	}, {
		name:     "single amd64 image is unchanged",
		children: []mutate.IndexAddendum{platformChild(t, "linux", "amd64")},
		wantArch: "amd64",
	}, {
		name: "multi platform index still resolves linux/amd64",
		children: []mutate.IndexAddendum{
			platformChild(t, "linux", "amd64"),
			platformChild(t, "linux", "arm64"),
		},
		wantArch: "amd64",
	}, {
		name: "multi platform index is left to platform selection",
		children: []mutate.IndexAddendum{
			platformChild(t, "linux", "arm64"),
			platformChild(t, "linux", "s390x"),
		},
		wantErr: "no child with platform linux/amd64",
	}}

	host := startRegistry(t)

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			image := fmt.Sprintf("%s/test/index-%d:v1", host, i)
			ref, err := name.ParseReference(image)
			require.NoError(t, err)
			require.NoError(t, remote.WriteIndex(ref, mutate.AppendManifests(empty.Index, tt.children...)))

			fetcher, err := New(nil, nil, nil)
			require.NoError(t, err)

			data, err := fetcher.FetchImageData(context.TODO(), image, nil, nil)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantArch, data.ConfigData.Architecture)
			assert.NotNil(t, data.ImageIndex)

			indexDigest, err := mutate.AppendManifests(empty.Index, tt.children...).Digest()
			require.NoError(t, err)
			assert.Equal(t, indexDigest.String(), data.Digest)
		})
	}
}

func TestFetchImageData_PlainManifest(t *testing.T) {
	t.Parallel()

	host := startRegistry(t)
	image := fmt.Sprintf("%s/test/plain:v1", host)

	ref, err := name.ParseReference(image)
	require.NoError(t, err)
	require.NoError(t, remote.Write(ref, platformImage(t, "linux", "arm64")))

	fetcher, err := New(nil, nil, nil)
	require.NoError(t, err)

	data, err := fetcher.FetchImageData(context.TODO(), image, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "arm64", data.ConfigData.Architecture)
	assert.Nil(t, data.ImageIndex)
}

func TestDescribesImage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		desc gcrv1.Descriptor
		want bool
	}{{
		name: "oci image manifest",
		desc: gcrv1.Descriptor{MediaType: types.OCIManifestSchema1, Platform: &gcrv1.Platform{OS: "linux", Architecture: "arm64"}},
		want: true,
	}, {
		name: "docker image manifest",
		desc: gcrv1.Descriptor{MediaType: types.DockerManifestSchema2, Platform: &gcrv1.Platform{OS: "linux", Architecture: "amd64"}},
		want: true,
	}, {
		name: "image without a platform",
		desc: gcrv1.Descriptor{MediaType: types.OCIManifestSchema1},
		want: true,
	}, {
		name: "buildkit attestation",
		desc: gcrv1.Descriptor{MediaType: types.OCIManifestSchema1, Platform: &gcrv1.Platform{OS: "unknown", Architecture: "unknown"}},
		want: false,
	}, {
		name: "referrer",
		desc: gcrv1.Descriptor{MediaType: types.OCIManifestSchema1, ArtifactType: "application/vnd.cncf.notary.signature"},
		want: false,
	}, {
		name: "nested index",
		desc: gcrv1.Descriptor{MediaType: types.OCIImageIndex},
		want: false,
	}, {
		name: "no media type",
		desc: gcrv1.Descriptor{},
		want: false,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, describesImage(tt.desc))
		})
	}
}
