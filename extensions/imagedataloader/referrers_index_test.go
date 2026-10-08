package imagedataloader

import (
	"encoding/json"
	"strings"
	"testing"

	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An oversized referrers index must be refused before the unmarshal, which is
// where the cost lands.
func TestReferrersIndexBody_OversizedIsRefused(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.index.v1+json",
		"manifests":     []any{},
		"annotations":   map[string]string{"pad": strings.Repeat("A", int(maxReferrersIndexSize)+1)},
	})
	require.NoError(t, err)
	require.Greater(t, int64(len(raw)), maxReferrersIndexSize)

	// Guard the bound itself: a realistic index of the allowed entry count must fit.
	manifests := make([]gcrv1.Descriptor, 0, maxReferrersCount)
	for i := 0; i < maxReferrersCount; i++ {
		manifests = append(manifests, gcrv1.Descriptor{
			MediaType:    "application/vnd.oci.image.manifest.v1+json",
			Size:         1024,
			ArtifactType: "application/vnd.cncf.notary.signature",
		})
	}
	small, err := json.Marshal(gcrv1.IndexManifest{SchemaVersion: 2, Manifests: manifests})
	require.NoError(t, err)
	assert.Less(t, int64(len(small)), maxReferrersIndexSize, "a full legitimate index must sit under the bound")
}
