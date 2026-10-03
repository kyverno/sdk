package imagedataloader

import (
	"github.com/google/go-containerregistry/pkg/logs"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const unknownPlatform = "unknown"

// imageForDescriptor resolves a descriptor to an image when a child can be selected
// unambiguously. It preserves indexes whose platform metadata does not identify a
// single child.
func imageForDescriptor(desc *remote.Descriptor) (gcrv1.Image, bool, error) {
	index, err := desc.ImageIndex()
	if err != nil {
		// ImageIndex rejects a descriptor only on its media type, so this is the ordinary
		// single manifest case rather than a fault, and there is no index to pick a child
		// from. Image resolves such a descriptor directly, and returns the same error for
		// the media types neither call supports, so continuing here hides nothing.
		logs.Debug.Printf("%s is not an image index, resolving the descriptor directly: %v", desc.Digest, err)
		image, err := desc.Image()
		return image, true, err
	}

	images, err := partial.FindManifests(index, describesImage)
	if err != nil {
		return nil, false, err
	}

	// A single image can be resolved directly. For multiple images, preserve the index when
	// platform metadata is ambiguous; otherwise let the registry platform selection choose a child.
	if len(images) != 1 {
		if hasAmbiguousPlatform(images) {
			return nil, false, nil
		}
		image, err := desc.Image()
		return image, true, err
	}

	image, err := index.Image(images[0].Digest)
	return image, true, err
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

// hasAmbiguousPlatform reports whether multiple Windows image descriptors target the same
// OS and architecture but specify different OS versions.
func hasAmbiguousPlatform(images []gcrv1.Descriptor) bool {
	if len(images) < 2 {
		return false
	}

	first := images[0].Platform
	if first == nil || first.OS != "windows" {
		return false
	}

	versions := make(map[string]struct{})
	for _, image := range images {
		platform := image.Platform
		if platform == nil ||
			platform.OS != first.OS ||
			platform.Architecture != first.Architecture {
			return false
		}
		versions[platform.OSVersion] = struct{}{}
	}

	return len(versions) > 1
}
