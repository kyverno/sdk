package imagedataloader

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestImageContextGetCacheHitReleasesReadLock(t *testing.T) {
	data := &ImageData{}
	ctx := &imageContext{
		list: map[string]*ImageData{"example.com/image:latest": data},
	}

	got, err := ctx.Get(context.Background(), "example.com/image:latest", nil, nil)
	require.NoError(t, err)
	require.Same(t, data, got)

	acquired := make(chan struct{})
	go func() {
		ctx.Lock()
		defer ctx.Unlock()
		close(acquired)
	}()

	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("write lock remained blocked after a cache hit")
	}
}
