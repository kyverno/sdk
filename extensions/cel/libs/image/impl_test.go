package image

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTagFromTaggedDigestReference(t *testing.T) {
	t.Parallel()

	cases := []struct {
		ref  string
		want string
	}{
		{
			ref:  "registry.k8s.io/kube-apiserver-arm64:latest@sha256:6aefddb645ee6963afd681b1845c661d0ea4c3b20ab9db86d9e753b203d385f2",
			want: "latest",
		},
		{
			ref:  "docker.io/library/alpine:v1.2.3@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1",
			want: "v1.2.3",
		},
		{
			ref:  "fictional.registry.example:10443/imagename:my_tag@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			want: "my_tag",
		},
		{
			ref:  "registry.k8s.io/kube-apiserver-arm64@sha256:6aefddb645ee6963afd681b1845c661d0ea4c3b20ab9db86d9e753b203d385f2",
			want: "",
		},
		{
			ref:  "registry.example:5000/repo@sha256:6aefddb645ee6963afd681b1845c661d0ea4c3b20ab9db86d9e753b203d385f2",
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.ref, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tagFromTaggedDigestReference(tc.ref))
		})
	}
}

func TestIdentifierFromReference(t *testing.T) {
	t.Parallel()

	ref, err := name.ParseReference("registry.k8s.io/kube-apiserver-arm64:latest@sha256:6aefddb645ee6963afd681b1845c661d0ea4c3b20ab9db86d9e753b203d385f2")
	require.NoError(t, err)
	assert.Equal(t, "latest@sha256:6aefddb645ee6963afd681b1845c661d0ea4c3b20ab9db86d9e753b203d385f2", identifierFromReference(ref))

	tagRef, err := name.ParseReference("registry.k8s.io/kube-apiserver-arm64:testtag")
	require.NoError(t, err)
	assert.Equal(t, "testtag", identifierFromReference(tagRef))
}
