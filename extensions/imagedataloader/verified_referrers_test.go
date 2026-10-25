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
	"github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testReferrerType = "application/vnd.test.attestation"

// GetPayload must only return referrer data recorded as verified, never falling
// back to whichever referrer of that type the registry lists.
func TestGetPayload_Referrer(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	repo, err := name.NewRepository(strings.TrimPrefix(srv.URL, "http://") + "/test/ref")
	require.NoError(t, err)

	var descs []gcrv1.Descriptor
	for _, p := range []string{`{"signed":false}`, `{"signed":true}`} {
		img, err := mutate.AppendLayers(empty.Image, static.NewLayer([]byte(p), types.MediaType("application/json")))
		require.NoError(t, err)
		dig, err := img.Digest()
		require.NoError(t, err)
		require.NoError(t, remote.Write(repo.Digest(dig.String()), img))
		descs = append(descs, gcrv1.Descriptor{Digest: dig, ArtifactType: testReferrerType})
	}

	img := &ImageData{
		nameRef:           repo.Tag("latest"),
		referrersData:     make(map[string]referrerData),
		referrersManifest: &gcrv1.IndexManifest{Manifests: descs},
	}
	attestation := v1beta1.Attestation{Name: "test", Referrer: &v1beta1.Referrer{Type: testReferrerType}}

	_, err = img.GetPayload(attestation)
	assert.ErrorContains(t, err, "cannot be fetched before verifying")
	assert.Empty(t, img.referrersData, "no referrer data may be fetched for an unverified type")

	img.AddVerifiedReferrer(descs[1])
	payload, err := img.GetPayload(attestation)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"signed": true}, payload)
}

func TestAddVerifiedReferrer(t *testing.T) {
	desc := func(c, artifactType string) gcrv1.Descriptor {
		return gcrv1.Descriptor{Digest: gcrv1.Hash{Algorithm: "sha256", Hex: strings.Repeat(c, 64)}, ArtifactType: artifactType}
	}
	a, b, other := desc("a", testReferrerType), desc("b", testReferrerType), desc("c", "application/vnd.other")

	img := &ImageData{}
	for _, d := range []gcrv1.Descriptor{a, b, a, other} {
		img.AddVerifiedReferrer(d)
	}
	assert.Equal(t, []gcrv1.Descriptor{a, b}, img.VerifiedReferrers(testReferrerType))
	assert.Equal(t, []gcrv1.Descriptor{other}, img.VerifiedReferrers("application/vnd.other"))

	// The getter returns a copy.
	img.VerifiedReferrers(testReferrerType)[0] = other
	assert.Equal(t, []gcrv1.Descriptor{a, b}, img.VerifiedReferrers(testReferrerType))
}
