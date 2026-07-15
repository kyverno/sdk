package image

import (
	"fmt"
	"strings"

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
	return types.String(identifierFromReference(v))
}

func imageTag(arg ref.Val) ref.Val {
	v, ok := arg.Value().(name.Reference)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	return types.String(tagFromReference(v))
}

// tagFromTaggedDigestReference extracts the tag from refs in repo:tag@digest form.
// go-containerregistry parses these as Digest, so the tag is not available via name.Tag.
func tagFromTaggedDigestReference(ref string) string {
	i := strings.Index(ref, "@")
	if i == -1 {
		return ""
	}
	refBeforeDigest := ref[:i]
	// Only treat : after the last / as a tag separator so registry ports
	// like registry.example:5000/repo@sha256:... are not mistaken for tags.
	slash := strings.LastIndex(refBeforeDigest, "/")
	j := strings.LastIndex(refBeforeDigest, ":")
	if j == -1 || j < slash {
		return ""
	}
	return refBeforeDigest[j+1:]
}

func tagFromReference(ref name.Reference) string {
	if t, ok := ref.(name.Tag); ok {
		return t.TagStr()
	}
	return tagFromTaggedDigestReference(ref.String())
}

func identifierFromReference(ref name.Reference) string {
	identifier := ref.Identifier()
	if digest, ok := ref.(name.Digest); ok {
		if tag := tagFromTaggedDigestReference(ref.String()); tag != "" {
			return fmt.Sprintf("%s@%s", tag, digest.DigestStr())
		}
	}
	return identifier
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
		return types.String("@" + digest.DigestStr())
	}
	// For tag references (including default "latest"), use ":" separator
	return types.String(":" + v.Identifier())
}
