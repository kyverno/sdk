package imagedata

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

var ContextType = types.NewOpaqueType("imagedata.Context")

type ContextInterface interface {
	GetImageData(string, []remote.Option) (map[string]any, error)
}

type Context struct {
	ContextInterface
}
