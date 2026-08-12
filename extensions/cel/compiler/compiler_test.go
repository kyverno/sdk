package compiler

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func newTestVariablesProvider() *VariablesProvider {
	return NewVariablesProvider(types.NewEmptyRegistry())
}

func TestCompileMatchCondition(t *testing.T) {
	env, err := NewBaseEnv()
	require.NoError(t, err)

	path := field.NewPath("matchConditions")

	t.Run("valid bool expression", func(t *testing.T) {
		mc := admissionregistrationv1.MatchCondition{
			Name:       "test",
			Expression: "true",
		}
		prog, errs := CompileMatchCondition(path.Index(0), env, mc)
		assert.Empty(t, errs)
		assert.NotNil(t, prog)
	})

	t.Run("invalid expression syntax", func(t *testing.T) {
		mc := admissionregistrationv1.MatchCondition{
			Name:       "test",
			Expression: "!!!invalid",
		}
		prog, errs := CompileMatchCondition(path.Index(0), env, mc)
		assert.Nil(t, prog)
		assert.NotEmpty(t, errs)
	})

	t.Run("non-bool output type returns error", func(t *testing.T) {
		mc := admissionregistrationv1.MatchCondition{
			Name:       "test",
			Expression: `"hello"`,
		}
		prog, errs := CompileMatchCondition(path.Index(0), env, mc)
		assert.Nil(t, prog)
		assert.NotEmpty(t, errs)
		assert.Contains(t, errs[0].Detail, "bool")
	})
}

func TestCompileMatchConditions(t *testing.T) {
	env, err := NewBaseEnv()
	require.NoError(t, err)

	path := field.NewPath("matchConditions")

	t.Run("empty slice returns nil", func(t *testing.T) {
		result, errs := CompileMatchConditions(path, env)
		assert.Nil(t, result)
		assert.Nil(t, errs)
	})

	t.Run("multiple valid conditions", func(t *testing.T) {
		result, errs := CompileMatchConditions(path, env,
			admissionregistrationv1.MatchCondition{Name: "a", Expression: "true"},
			admissionregistrationv1.MatchCondition{Name: "b", Expression: "false"},
		)
		assert.Empty(t, errs)
		assert.Len(t, result, 2)
	})

	t.Run("one invalid condition accumulates errors", func(t *testing.T) {
		result, errs := CompileMatchConditions(path, env,
			admissionregistrationv1.MatchCondition{Name: "a", Expression: "true"},
			admissionregistrationv1.MatchCondition{Name: "b", Expression: "!!!bad"},
		)
		assert.NotEmpty(t, errs)
		assert.Len(t, result, 1)
	})
}

func TestCompileVariable(t *testing.T) {
	env, err := NewBaseEnv()
	require.NoError(t, err)

	path := field.NewPath("variables")

	t.Run("valid expression registers field", func(t *testing.T) {
		provider := newTestVariablesProvider()
		v := admissionregistrationv1.Variable{
			Name:       "myVar",
			Expression: "1 + 1",
		}
		prog, errs := CompileVariable(path.Index(0), env, provider, v)
		assert.Empty(t, errs)
		assert.NotNil(t, prog)
		names, ok := provider.FindStructFieldNames(VariablesType.DeclaredTypeName())
		assert.True(t, ok)
		assert.Contains(t, names, "myVar")
	})

	t.Run("invalid expression returns error", func(t *testing.T) {
		provider := newTestVariablesProvider()
		v := admissionregistrationv1.Variable{
			Name:       "bad",
			Expression: "!!!invalid",
		}
		prog, errs := CompileVariable(path.Index(0), env, provider, v)
		assert.Nil(t, prog)
		assert.NotEmpty(t, errs)
	})
}

func TestCompileVariables(t *testing.T) {
	env, err := NewBaseEnv()
	require.NoError(t, err)

	path := field.NewPath("variables")

	t.Run("empty slice returns nil", func(t *testing.T) {
		provider := newTestVariablesProvider()
		result, errs := CompileVariables(path, env, provider)
		assert.Nil(t, result)
		assert.Nil(t, errs)
	})

	t.Run("valid variables compiled into map", func(t *testing.T) {
		provider := newTestVariablesProvider()
		result, errs := CompileVariables(path, env, provider,
			admissionregistrationv1.Variable{Name: "x", Expression: "1"},
			admissionregistrationv1.Variable{Name: "y", Expression: "2"},
		)
		assert.Empty(t, errs)
		require.Len(t, result, 2)
		assert.NotNil(t, result["x"])
		assert.NotNil(t, result["y"])
	})

	t.Run("invalid variable accumulates error", func(t *testing.T) {
		provider := newTestVariablesProvider()
		result, errs := CompileVariables(path, env, provider,
			admissionregistrationv1.Variable{Name: "good", Expression: "1"},
			admissionregistrationv1.Variable{Name: "bad", Expression: "!!!"},
		)
		assert.NotEmpty(t, errs)
		require.Len(t, result, 1)
		assert.NotNil(t, result["good"])
	})
}

func TestCompileValidation(t *testing.T) {
	env, err := NewBaseEnv()
	require.NoError(t, err)

	path := field.NewPath("validations")

	t.Run("valid bool expression no messageExpression", func(t *testing.T) {
		rule := admissionregistrationv1.Validation{
			Expression: "true",
			Message:    "denied",
		}
		v, errs := CompileValidation(path.Index(0), env, rule)
		assert.Empty(t, errs)
		assert.NotNil(t, v.Program)
		assert.Nil(t, v.MessageExpression)
		assert.Equal(t, "denied", v.Message)
	})

	t.Run("valid expression with string messageExpression", func(t *testing.T) {
		rule := admissionregistrationv1.Validation{
			Expression:        "true",
			MessageExpression: `"error: " + "msg"`,
		}
		v, errs := CompileValidation(path.Index(0), env, rule)
		assert.Empty(t, errs)
		assert.NotNil(t, v.Program)
		assert.NotNil(t, v.MessageExpression)
	})

	t.Run("non-bool expression returns error", func(t *testing.T) {
		rule := admissionregistrationv1.Validation{
			Expression: `"not a bool"`,
		}
		v, errs := CompileValidation(path.Index(0), env, rule)
		assert.NotEmpty(t, errs)
		assert.Nil(t, v.Program)
		assert.Contains(t, errs[0].Detail, "bool")
	})

	t.Run("invalid expression syntax returns error", func(t *testing.T) {
		rule := admissionregistrationv1.Validation{
			Expression: "!!!bad",
		}
		v, errs := CompileValidation(path.Index(0), env, rule)
		assert.NotEmpty(t, errs)
		assert.Nil(t, v.Program)
	})

	t.Run("non-string messageExpression returns error", func(t *testing.T) {
		rule := admissionregistrationv1.Validation{
			Expression:        "true",
			MessageExpression: "42",
		}
		v, errs := CompileValidation(path.Index(0), env, rule)
		assert.NotEmpty(t, errs)
		assert.Nil(t, v.Program)
	})

	t.Run("invalid messageExpression syntax returns error", func(t *testing.T) {
		rule := admissionregistrationv1.Validation{
			Expression:        "true",
			MessageExpression: "!!!bad",
		}
		v, errs := CompileValidation(path.Index(0), env, rule)
		assert.NotEmpty(t, errs)
		assert.Nil(t, v.Program)
	})
}

func TestCompileAuditAnnotation(t *testing.T) {
	env, err := NewBaseEnv()
	require.NoError(t, err)

	path := field.NewPath("auditAnnotations")

	t.Run("string value expression", func(t *testing.T) {
		aa := admissionregistrationv1.AuditAnnotation{
			Key:             "k",
			ValueExpression: `"value"`,
		}
		prog, errs := CompileAuditAnnotation(path.Index(0), env, aa)
		assert.Empty(t, errs)
		assert.NotNil(t, prog)
	})

	t.Run("null value expression", func(t *testing.T) {
		aa := admissionregistrationv1.AuditAnnotation{
			Key:             "k",
			ValueExpression: "null",
		}
		prog, errs := CompileAuditAnnotation(path.Index(0), env, aa)
		assert.Empty(t, errs)
		assert.NotNil(t, prog)
	})

	t.Run("non-string non-null returns error", func(t *testing.T) {
		aa := admissionregistrationv1.AuditAnnotation{
			Key:             "k",
			ValueExpression: "42",
		}
		prog, errs := CompileAuditAnnotation(path.Index(0), env, aa)
		assert.Nil(t, prog)
		assert.NotEmpty(t, errs)
	})

	t.Run("invalid syntax returns error", func(t *testing.T) {
		aa := admissionregistrationv1.AuditAnnotation{
			Key:             "k",
			ValueExpression: "!!!",
		}
		prog, errs := CompileAuditAnnotation(path.Index(0), env, aa)
		assert.Nil(t, prog)
		assert.NotEmpty(t, errs)
	})
}

func TestCompileAuditAnnotations(t *testing.T) {
	env, err := NewBaseEnv()
	require.NoError(t, err)

	path := field.NewPath("auditAnnotations")

	t.Run("empty returns nil", func(t *testing.T) {
		result, errs := CompileAuditAnnotations(path, env)
		assert.Nil(t, result)
		assert.Nil(t, errs)
	})

	t.Run("valid annotations compiled into map", func(t *testing.T) {
		result, errs := CompileAuditAnnotations(path, env,
			admissionregistrationv1.AuditAnnotation{Key: "a", ValueExpression: `"v1"`},
			admissionregistrationv1.AuditAnnotation{Key: "b", ValueExpression: `"v2"`},
		)
		assert.Empty(t, errs)
		require.Len(t, result, 2)
		assert.NotNil(t, result["a"])
		assert.NotNil(t, result["b"])
	})

	t.Run("invalid annotation accumulates error", func(t *testing.T) {
		result, errs := CompileAuditAnnotations(path, env,
			admissionregistrationv1.AuditAnnotation{Key: "a", ValueExpression: `"v1"`},
			admissionregistrationv1.AuditAnnotation{Key: "b", ValueExpression: "!!!"},
		)
		assert.NotEmpty(t, errs)
		require.Len(t, result, 1)
		assert.NotNil(t, result["a"])
	})
}
