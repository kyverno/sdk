package imagedataloader

import (
	"context"
	"testing"
)

func TestImageContextGetCacheHitReleasesReadLock(t *testing.T) {
	want := &ImageData{}
	ctx := &imageContext{
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
