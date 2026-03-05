package policy

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMakeEvaluation_SetsResultAndError(t *testing.T) {
	e := MakeEvaluation(true, nil)
	assert.True(t, e.Result)
	assert.Nil(t, e.Error)
}

func TestMakeEvaluation_WithError(t *testing.T) {
	err := errors.New("evaluation failed")
	e := MakeEvaluation(false, err)
	assert.False(t, e.Result)
	assert.Equal(t, err, e.Error)
}

func TestMakeEvaluation_ResultOnly(t *testing.T) {
	e := MakeEvaluation("allowed", nil)
	assert.Equal(t, "allowed", e.Result)
	assert.Nil(t, e.Error)
}
