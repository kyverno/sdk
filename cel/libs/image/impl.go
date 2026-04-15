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

// imageIdentifierWithSeparator returns the image identifier with its separator.
// When both a tag and digest are present, the digest takes precedence (consistent with identifier()).
// Examples:
//   - nginx:1.25 -> ":1.25"
//   - nginx@sha256:abc123 -> "@sha256:abc123"
//   - nginx:1.25@sha256:abc123 -> "@sha256:abc123"
//   - nginx (no tag) -> ":latest" (default tag)
func imageIdentifierWithSeparator(arg ref.Val) ref.Val {
	v, ok := arg.Value().(name.Reference)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	// Check for digest first (digest takes precedence when both tag and digest are present)
	if digest, ok := v.(name.Digest); ok {
		if digestStr := digest.DigestStr(); digestStr != "" {
			return types.String("@" + digestStr)
		}
	}
	// Check for tag
	if tag, ok := v.(name.Tag); ok {
		if tagStr := tag.TagStr(); tagStr != "" {
			return types.String(":" + tagStr)
		}
	}
	// Fallback to default identifier (e.g., "latest")
	identifier := v.Identifier()
	if identifier != "" {
		return types.String(":" + identifier)
	}
	return types.String("")
}
