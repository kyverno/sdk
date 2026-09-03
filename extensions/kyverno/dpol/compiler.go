package dpol

import (
	"fmt"

	policiesv1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
	"github.com/kyverno/sdk/extensions/cel/compiler"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/cel/environment"
)

var compileError = "deleting policy compiler " + dpolCompilerVersion.String() + " error: %s"

type Compiler interface {
	Compile(policy policiesv1.DeletingPolicyLike) (*Policy, field.ErrorList)
}

func NewCompiler() Compiler {
	return &compilerImpl{}
}

type compilerImpl struct{}

func (c *compilerImpl) Compile(policy policiesv1.DeletingPolicyLike) (*Policy, field.ErrorList) {
	var allErrs field.ErrorList
	dpolEnvSet, variablesProvider, err := NewEnv()
	if err != nil {
		return nil, append(allErrs, field.InternalError(nil, fmt.Errorf(compileError, err)))
	}

	env, err := dpolEnvSet.Env(environment.StoredExpressions)
	if err != nil {
		return nil, append(allErrs, field.InternalError(nil, fmt.Errorf(compileError, err)))
	}

	path := field.NewPath("spec")
	spec := policy.GetDeletingPolicySpec()

	variables, errs := compiler.CompileVariables(path.Child("variables"), env, variablesProvider, spec.Variables...)
	if errs != nil {
		return nil, append(allErrs, errs...)
	}

	conditions, errs := compiler.CompileMatchConditions(path.Child("conditions"), env, spec.Conditions...)
	if errs != nil {
		return nil, append(allErrs, errs...)
	}

	return &Policy{
		matchConstraints: spec.MatchConstraints,
		conditions:       conditions,
		variables:        variables,
	}, nil
}
