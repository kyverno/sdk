package sources

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
)

func TestNewFs_IncludesMatchingEntries(t *testing.T) {
	ctx := context.Background()
	mapfs := fstest.MapFS{
		"foo.go":     {Data: []byte("package main")},
		"bar.go":     {Data: []byte("package main")},
		"readme.txt": {Data: []byte("readme")},
		"sub/baz.go": {Data: []byte("package sub")},
	}

	src := NewFs(mapfs, func(path string, entry fs.DirEntry) bool {
		return !entry.IsDir() && strings.HasSuffix(path, ".go")
	})

	entries, err := src.Load(ctx)
	assert.NoError(t, err)
	assert.Len(t, entries, 3)

	paths := make([]string, len(entries))
	for i, e := range entries {
		paths[i] = e.Path
	}
	assert.Contains(t, paths, "foo.go")
	assert.Contains(t, paths, "bar.go")
	assert.Contains(t, paths, "sub/baz.go")
	assert.NotContains(t, paths, "readme.txt")
}

func TestNewFs_ExcludesDirectoriesWhenPredicateFalse(t *testing.T) {
	ctx := context.Background()
	mapfs := fstest.MapFS{
		"file.txt": {Data: []byte("x")},
		"dir":      {Data: nil}, // dir is represented as empty file in MapFS; IsDir() may vary
	}

	src := NewFs(mapfs, func(path string, entry fs.DirEntry) bool {
		return !entry.IsDir()
	})

	entries, err := src.Load(ctx)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(entries), 1)
	for _, e := range entries {
		assert.False(t, e.DirEntry.IsDir(), "should not include directories")
	}
}

func TestNewFsErr_IncludesMatchingAndAggregatesErrors(t *testing.T) {
	ctx := context.Background()
	mapfs := fstest.MapFS{
		"a.yaml": {Data: []byte("a")},
		"b.yaml": {Data: []byte("b")},
		"c.txt":  {Data: []byte("c")},
	}

	var predicateErrors int
	src := NewFsErr(mapfs, func(path string, entry fs.DirEntry) (bool, error) {
		if strings.HasSuffix(path, ".txt") {
			predicateErrors++
			return false, assert.AnError
		}
		return strings.HasSuffix(path, ".yaml"), nil
	})

	entries, err := src.Load(ctx)
	assert.Error(t, err)
	assert.Len(t, entries, 2)
	paths := make([]string, len(entries))
	for i, e := range entries {
		paths[i] = e.Path
	}
	assert.Contains(t, paths, "a.yaml")
	assert.Contains(t, paths, "b.yaml")
	assert.Equal(t, 1, predicateErrors)
}
