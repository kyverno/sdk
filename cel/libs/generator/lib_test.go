package generator

import (
	"testing"

	"github.com/kyverno/sdk/cel/compiler"
	"github.com/stretchr/testify/assert"
)

func TestLib(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)

	env, err := base.Extend(
		Lib(nil, nil),
	)
	assert.NoError(t, err)
	assert.NotNil(t, env)
}

func Test_lib_LibraryName(t *testing.T) {
	var l lib
	assert.Equal(t, libraryName, l.LibraryName())
}
