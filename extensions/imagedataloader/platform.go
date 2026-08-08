package imagedataloader

import (
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
		return desc.Image()
	}

	images, err := partial.FindManifests(index, describesImage)
	if err != nil {
		return nil, err
	}

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
