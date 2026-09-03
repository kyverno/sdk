package imagedataloader

import (
	"github.com/google/go-containerregistry/pkg/logs"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const unknownPlatform = "unknown"

// imageForDescriptor resolves an index holding a single image by digest, Descriptor.Image
// would select it by platform and fail on anything that is not linux/amd64.
func imageForDescriptor(desc *remote.Descriptor) (gcrv1.Image, error) {
	index, err := desc.ImageIndex()
	if err != nil {
		// ImageIndex rejects a descriptor only on its media type, so this is the ordinary
		// single manifest case rather than a fault, and there is no index to pick a child
		// from. Image resolves such a descriptor directly, and returns the same error for
		// the media types neither call supports, so continuing here hides nothing.
		logs.Debug.Printf("%s is not an image index, resolving the descriptor directly: %v", desc.Digest, err)
		return desc.Image()
	}

	images, err := partial.FindManifests(index, describesImage)
	if err != nil {
		return nil, err
	}

	// zero when no child of the index describes an image, more than one when the index is
	// genuinely multi platform. neither has a single answer, so both keep platform selection
	if len(images) != 1 {
		return desc.Image()
	}

	return index.Image(images[0].Digest)
}

// referrers carry an artifact type, buildkit attestations an unknown platform
func describesImage(desc gcrv1.Descriptor) bool {
	if !desc.MediaType.IsImage() || desc.ArtifactType != "" {
		return false
	}
	if desc.Platform == nil {
		return true
	}
	return desc.Platform.OS != unknownPlatform && desc.Platform.Architecture != unknownPlatform
}
