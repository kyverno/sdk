package imagedataloader

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedIndex serves a prepared body, standing in for an index go-containerregistry
// has already fetched and buffered: RawManifest returns those bytes, and
// IndexManifest is the unmarshal the bound is there to gate.
type fixedIndex struct {
	raw            []byte
	unmarshalCalls *int
}

func (f *fixedIndex) RawManifest() ([]byte, error) { return f.raw, nil }

func (f *fixedIndex) IndexManifest() (*gcrv1.IndexManifest, error) {
	if f.unmarshalCalls != nil {
		*f.unmarshalCalls++
	}
	m := &gcrv1.IndexManifest{}
	if err := json.Unmarshal(f.raw, m); err != nil {
		return nil, err
	}
	return m, nil
}

func indexBody(t *testing.T, padding int) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests":     []any{},
		"annotations":   map[string]string{"pad": strings.Repeat("A", padding)},
	})
	require.NoError(t, err)
	return raw
}

// The point of the bound is that the unmarshal never runs, so assert on that and
// not merely on the returned error.
func TestReferrersIndexManifest_OversizedBodySkipsTheUnmarshal(t *testing.T) {
	calls := 0
	idx := &fixedIndex{raw: indexBody(t, int(maxReferrersIndexSize)+1), unmarshalCalls: &calls}

	_, err := referrersIndexManifest(idx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "index size")
	assert.Equal(t, 0, calls, "the unmarshal must not run for an oversized body")
}

func TestReferrersIndexManifest_WithinLimitUnmarshals(t *testing.T) {
	calls := 0
	idx := &fixedIndex{raw: indexBody(t, 1024), unmarshalCalls: &calls}

	m, err := referrersIndexManifest(idx)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Equal(t, 1, calls)
}

// Guard the bound itself: a full legitimate index must fit, or the bound would
// reject real images.
func TestReferrersIndexManifest_FullLegitimateIndexFits(t *testing.T) {
	manifests := make([]gcrv1.Descriptor, 0, maxReferrersCount)
	for i := 0; i < maxReferrersCount; i++ {
		h, err := gcrv1.NewHash(fmt.Sprintf("sha256:%064x", i))
		require.NoError(t, err)
		manifests = append(manifests, gcrv1.Descriptor{
			MediaType:    "application/vnd.oci.image.manifest.v1+json",
			Digest:       h,
			Size:         1024,
			ArtifactType: "application/vnd.cncf.notary.signature",
			Annotations:  map[string]string{"org.opencontainers.image.created": "2026-10-08T00:00:00Z"},
		})
	}
	raw, err := json.Marshal(gcrv1.IndexManifest{SchemaVersion: 2, Manifests: manifests})
	require.NoError(t, err)

	m, err := referrersIndexManifest(&fixedIndex{raw: raw})
	require.NoError(t, err)
	assert.Len(t, m.Manifests, maxReferrersCount)
}

// A limit at the top of the int64 range must not wrap the one-byte probe into a
// negative LimitReader count, which would read nothing and report success.
func TestReadLayerLimited_MaxInt64LimitStillReads(t *testing.T) {
	blob := gzipBytes(t, 4096)

	b, err := readLayerLimited(layerFrom(t, blob, nil), 1<<62)
	require.NoError(t, err)
	assert.Len(t, b, 4096)

	b, err = readLayerLimited(layerFrom(t, blob, nil), math.MaxInt64)
	require.NoError(t, err, "an unincrementable limit must still read the payload")
	assert.Len(t, b, 4096, "must not silently return an empty payload")
}
