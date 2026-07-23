package imagedata

import "github.com/google/go-containerregistry/pkg/v1/remote"

// a type that stores a function that implements the GetImageData method in the libraries
// context interface. when GetImageData on it is called it will invoke this internal function
// with the same arguments
type ContextMock struct {
	GetImageDataFunc func(string, []remote.Option) (map[string]any, error)
}

func (mock *ContextMock) GetImageData(n string, _ []remote.Option) (map[string]any, error) {
	return mock.GetImageDataFunc(n, nil)
}
