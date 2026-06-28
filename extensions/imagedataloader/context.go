package imagedataloader

import (
	"context"
	"sync"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sync/errgroup"
	k8scorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

type imageContext struct {
	sync.RWMutex
	f    Fetcher
	list map[string]*ImageData
}

var workers = 20

// ImageContext stores a list of imagedata, it lives as long as
// the admission request. Get request for images either returned a prefetched image or
// fetches it from the registry. It is used to share image data for a policy across policies
type ImageContext interface {
	AddImages(ctx context.Context, images []string, opts ...Option) error
	Get(ctx context.Context, image string, opts ...Option) (*ImageData, error)
}

// Creates an image data loader along with a cache that stores images. Calling .Get
// on that type performs a read from that cache and fallback to calling the remote if
// the image was not found
func NewImageContext(lister k8scorev1.SecretInterface, opts []remote.Option) (ImageContext, error) {
	idl, err := New(lister, opts)
	if err != nil {
		return nil, err
	}
	return &imageContext{
		f:    idl,
		list: make(map[string]*ImageData),
	}, nil
}

// this is where i pass non standard options to the imagedataloader. this gets called during ivpol.Evaluate
func (idc *imageContext) AddImages(ctx context.Context, images []string, opts ...Option) error {
	idc.Lock()
	defer idc.Unlock()

	var g errgroup.Group
	g.SetLimit(workers)

	for _, img := range images {
		g.Go(func() error {
			if _, found := idc.list[img]; found {
				return nil
			}

			data, err := idc.f.FetchImageData(ctx, img, opts...)
			if err != nil {
				return err
			}
			idc.list[img] = data
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	return nil
}

func (idc *imageContext) Get(ctx context.Context, image string, opts ...Option) (*ImageData, error) {
	idc.RLock()
	if data, found := idc.list[image]; found {
		return data, nil
	}
	idc.RUnlock()

	data, err := idc.f.FetchImageData(ctx, image, opts...)
	if err != nil {
		return nil, err
	}
	idc.Lock()
	defer idc.Unlock()
	idc.list[image] = data

	return data, nil
}
