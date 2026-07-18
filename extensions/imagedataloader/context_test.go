package imagedataloader

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type blockingFetcher struct {
	started chan string
	release chan struct{}
	mu      sync.Mutex
	calls   map[string]int
}

func (f *blockingFetcher) fetch(_ context.Context, image string, _ []remote.Option, _ []name.Option) (*ImageData, error) {
	f.mu.Lock()
	f.calls[image]++
	f.mu.Unlock()
	f.started <- image
	<-f.release
	return &ImageData{}, nil
}

type fetcherFunc func(context.Context, string, []remote.Option, []name.Option) (*ImageData, error)

func (f fetcherFunc) FetchImageData(ctx context.Context, image string, authOpts []remote.Option, nameOpts []name.Option) (*ImageData, error) {
	return f(ctx, image, authOpts, nameOpts)
}

func TestImageContextAddImagesConcurrent(t *testing.T) {
	const imageCount = 100
	fetcher := &blockingFetcher{
		started: make(chan string, imageCount),
		release: make(chan struct{}),
		calls:   make(map[string]int),
	}
	ctx := &imageContext{
		f:    fetcherFunc(fetcher.fetch),
		list: make(map[string]*ImageData),
	}
	images := make([]string, 0, imageCount+1)
	for i := range imageCount {
		images = append(images, nameFromIndex(i))
	}
	images = append(images, images[0])

	done := make(chan error, 1)
	go func() {
		done <- ctx.AddImages(context.Background(), images, nil, nil)
	}()

	for range min(workers, imageCount) {
		select {
		case <-fetcher.started:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent image fetches")
		}
	}
	close(fetcher.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("AddImages returned an error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AddImages did not complete")
	}

	if got := len(ctx.list); got != imageCount {
		t.Fatalf("cached %d images, want %d", got, imageCount)
	}
	fetcher.mu.Lock()
	defer fetcher.mu.Unlock()
	for _, image := range images[:imageCount] {
		if got := fetcher.calls[image]; got != 1 {
			t.Fatalf("fetched %q %d times, want 1", image, got)
		}
	}
}

func TestImageContextGetCacheHitReleasesReadLock(t *testing.T) {
	want := &ImageData{}
	ctx := &imageContext{
		f: fetcherFunc(func(context.Context, string, []remote.Option, []name.Option) (*ImageData, error) {
			t.Fatal("cache hit fetched from the registry")
			return nil, nil
		}),
		list: map[string]*ImageData{"cached": want},
	}

	got, err := ctx.Get(context.Background(), "cached", nil, nil)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if got != want {
		t.Fatal("Get returned the wrong cached image data")
	}
	if !ctx.TryLock() {
		t.Fatal("Get retained the read lock after a cache hit")
	}
	ctx.Unlock()
}

func nameFromIndex(index int) string {
	return fmt.Sprintf("registry.example.com/image-%d", index)
}
