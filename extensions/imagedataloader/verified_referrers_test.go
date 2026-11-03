package imagedataloader

import (
	"net/http/httptest"
	"strings"
	"sync"
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
	img, descs := pushReferrers(t, `{"signed":false}`, `{"signed":true}`)
	attestation := v1beta1.Attestation{Name: "test", Referrer: &v1beta1.Referrer{Type: testReferrerType}}

	_, err := img.GetPayload(attestation)
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

// pushReferrers publishes a subject image with one referrer of testReferrerType
// per payload, and returns ImageData for the subject plus the referrer
// descriptors in payload order. Nothing is preloaded, so the first calls go to
// the registry.
func pushReferrers(t *testing.T, payloads ...string) (*ImageData, []gcrv1.Descriptor) {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)
	repo, err := name.NewRepository(strings.TrimPrefix(srv.URL, "http://") + "/test/ref")
	require.NoError(t, err)

	subject, err := mutate.AppendLayers(empty.Image, static.NewLayer([]byte("subject"), types.MediaType("application/octet-stream")))
	require.NoError(t, err)
	tag := repo.Tag("latest")
	require.NoError(t, remote.Write(tag, subject))
	subjectDesc, err := remote.Head(tag)
	require.NoError(t, err)

	descs := make([]gcrv1.Descriptor, 0, len(payloads))
	for _, p := range payloads {
		img, err := mutate.AppendLayers(empty.Image, static.NewLayer([]byte(p), types.MediaType("application/json")))
		require.NoError(t, err)
		img = mutate.Subject(mutate.ConfigMediaType(img, testReferrerType), *subjectDesc).(gcrv1.Image)
		dig, err := img.Digest()
		require.NoError(t, err)
		require.NoError(t, remote.Write(repo.Digest(dig.String()), img))
		descs = append(descs, gcrv1.Descriptor{Digest: dig, ArtifactType: testReferrerType})
	}

	return &ImageData{
		ImageDescriptor: ImageDescriptor{ImageReference: ImageReference{Digest: subjectDesc.Digest.String()}},
		nameRef:         tag,
	}, descs
}

// Kyverno verifies referrers of one image in parallel, so every method it calls
// during verification must be safe to call concurrently. Run with -race.
func TestImageData_ConcurrentUse(t *testing.T) {
	payloads := []string{`{"n":0}`, `{"n":1}`, `{"n":2}`, `{"n":3}`}
	img, descs := pushReferrers(t, payloads...)
	referrer := v1beta1.Attestation{Name: "referrer", Referrer: &v1beta1.Referrer{Type: testReferrerType}}
	intoto := v1beta1.Attestation{Name: "intoto", InToto: &v1beta1.InToto{Type: "https://example.com/predicate"}}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			referrers, err := img.FetchReferrers(testReferrerType)
			if !assert.NoError(t, err) {
				return
			}
			assert.Len(t, referrers, len(descs))
			for _, desc := range descs {
				_, err := img.FetchReference(desc.Digest.String())
				assert.NoError(t, err)
				_, _, err = img.FetchReferrerData(desc)
				assert.NoError(t, err)
				img.AddVerifiedReferrer(desc)
				_, err = img.GetPayload(referrer)
				assert.NoError(t, err)
				assert.NotEmpty(t, img.VerifiedReferrers(testReferrerType))
			}
			img.AddVerifiedIntotoPayloads(intoto.InToto.Type, []byte(`{"intoto":true}`))
			_, err = img.GetPayload(intoto)
			assert.NoError(t, err)
		})
	}
	wg.Wait()

	assert.ElementsMatch(t, descs, img.VerifiedReferrers(testReferrerType))
	assert.Len(t, img.referrersData, len(descs))
	for n, desc := range descs {
		b, _, err := img.FetchReferrerData(desc)
		require.NoError(t, err)
		assert.Equal(t, payloads[n], string(b))
	}
}

func TestSetVerifiedReferrers(t *testing.T) {
	img, descs := pushReferrers(t, `{"n":0}`, `{"n":1}`, `{"n":2}`, `{"n":3}`)
	a, b, c, unverified := descs[0], descs[1], descs[2], descs[3]
	other := gcrv1.Descriptor{Digest: gcrv1.Hash{Algorithm: "sha256", Hex: strings.Repeat("d", 64)}, ArtifactType: "application/vnd.other"}
	attestation := v1beta1.Attestation{Name: "test", Referrer: &v1beta1.Referrer{Type: testReferrerType}}

	for _, d := range []gcrv1.Descriptor{a, b, c, other} {
		img.AddVerifiedReferrer(d)
	}

	// The recorded list is reordered and narrowed to descs. Repeated digests,
	// digests never recorded and those recorded for another type are dropped.
	// A descriptor is matched by digest alone, and the recorded one is kept.
	bByDigest := gcrv1.Descriptor{Digest: b.Digest}
	given := []gcrv1.Descriptor{c, bByDigest, c, unverified, other}
	img.SetVerifiedReferrers(testReferrerType, given)
	assert.Equal(t, []gcrv1.Descriptor{c, b}, img.VerifiedReferrers(testReferrerType))
	assert.Equal(t, []gcrv1.Descriptor{other}, img.VerifiedReferrers("application/vnd.other"), "other types are untouched")

	// GetPayload returns the first entry.
	payload, err := img.GetPayload(attestation)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"n": 2.0}, payload)

	// The recorded list does not alias the caller's slice.
	given[0] = a
	assert.Equal(t, []gcrv1.Descriptor{c, b}, img.VerifiedReferrers(testReferrerType))

	// What was dropped is no longer verified, and can only come back through
	// AddVerifiedReferrer.
	img.SetVerifiedReferrers(testReferrerType, []gcrv1.Descriptor{a, c})
	assert.Equal(t, []gcrv1.Descriptor{c}, img.VerifiedReferrers(testReferrerType))
	img.AddVerifiedReferrer(a)
	assert.Equal(t, []gcrv1.Descriptor{c, a}, img.VerifiedReferrers(testReferrerType))

	// An empty list clears the type, so GetPayload fails closed again.
	img.SetVerifiedReferrers(testReferrerType, nil)
	assert.Empty(t, img.VerifiedReferrers(testReferrerType))
	_, err = img.GetPayload(attestation)
	assert.ErrorContains(t, err, "cannot be fetched before verifying")
}

// SetVerifiedReferrers chooses among verified referrers; it must never be a way
// to mark one verified.
func TestSetVerifiedReferrers_DoesNotVerify(t *testing.T) {
	img, descs := pushReferrers(t, `{"signed":false}`)
	attestation := v1beta1.Attestation{Name: "test", Referrer: &v1beta1.Referrer{Type: testReferrerType}}

	listed, err := img.FetchReferrers(testReferrerType)
	require.NoError(t, err)
	require.Len(t, listed, len(descs))

	img.SetVerifiedReferrers(testReferrerType, listed)
	assert.Empty(t, img.VerifiedReferrers(testReferrerType))
	_, err = img.GetPayload(attestation)
	assert.ErrorContains(t, err, "cannot be fetched before verifying")
	assert.Empty(t, img.referrersData, "no referrer data may be fetched for an unverified type")
}
