package image

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/go-containerregistry/pkg/name"
)

func isImage(arg ref.Val) ref.Val {
	str, ok := arg.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	_, err := name.ParseReference(str)
	return types.Bool(err == nil)
}

func stringToImage(arg ref.Val) ref.Val {
	str, ok := arg.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	v, err := name.ParseReference(str)
	if err != nil {
		return types.WrapErr(err)
	}
	return Image{v}
}

func imageContainsDigest(arg ref.Val) ref.Val {
	v, ok := arg.Value().(name.Reference)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	if digest, ok := v.(name.Digest); ok {
		return types.Bool(len(digest.DigestStr()) != 0)
	}
	return types.False
}

func imageRegistry(arg ref.Val) ref.Val {
	v, ok := arg.Value().(name.Reference)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	return types.String(v.Context().RegistryStr())
}

func imageRepository(arg ref.Val) ref.Val {
	v, ok := arg.Value().(name.Reference)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	return types.String(v.Context().RepositoryStr())
}

func imageIdentifier(arg ref.Val) ref.Val {
	v, ok := arg.Value().(name.Reference)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	return types.String(v.Identifier())
}

func imageTag(arg ref.Val) ref.Val {
	v, ok := arg.Value().(name.Reference)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	var tag string
	if v, ok := v.(name.Tag); ok {
		tag = v.TagStr()
	}
	return types.String(tag)
}

func imageDigest(arg ref.Val) ref.Val {
	v, ok := arg.Value().(name.Reference)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	var digest string
	if v, ok := v.(name.Digest); ok {
		digest = v.DigestStr()
	}
	return types.String(digest)
}

// imageIdentifierWithSeparator returns the image identifier (tag and/or digest)
// including the appropriate separator(s).
// Examples:
//   - nginx:1.25 -> ":1.25"
//   - nginx@sha256:abc123 -> "@sha256:abc123"
//   - nginx:1.25@sha256:abc123 -> ":1.25@sha256:abc123"
//   - nginx (no tag) -> ":latest" (default tag)
func imageIdentifierWithSeparator(arg ref.Val) ref.Val {
	v, ok := arg.Value().(name.Reference)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	// Get the full reference string (e.g., "registry.io/repo:tag@digest")
	refStr := v.String()
	// Get the registry/repository part (e.g., "registry.io/repo")
	repoStr := v.Context().String()
	// The identifier with separator is what remains after the repository
	if len(refStr) > len(repoStr) {
		return types.String(refStr[len(repoStr):])
	}
	// If the reference has no explicit tag/digest in the string but has a default identifier,
	// return it with the ":" separator (this handles the default "latest" tag case)
	identifier := v.Identifier()
	if identifier != "" {
		return types.String(":" + identifier)
	}
	return types.String("")
}
