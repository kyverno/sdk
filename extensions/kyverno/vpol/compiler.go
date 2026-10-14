package vpol

import (
	"fmt"

	"github.com/google/cel-go/cel"
	policieskyvernoio "github.com/kyverno/api/api/policies.kyverno.io"
	policiesv1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
	"github.com/kyverno/sdk/extensions/cel/compiler"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/cel/environment"
)

var (
	compileError = "validating policy compiler " + vpolCompilerVersion.String() + " error: %s"
)

type Compiler interface {
	Compile(policy policiesv1.ValidatingPolicyLike) (*Policy, field.ErrorList)
}

func NewCompiler() Compiler {
	return &compilerImpl{}
}

type compilerImpl struct{}

func (c *compilerImpl) Compile(policy policiesv1.ValidatingPolicyLike) (*Policy, field.ErrorList) {
	return c.compileForKubernetes(policy)
}

func (c *compilerImpl) compileForKubernetes(policy policiesv1.ValidatingPolicyLike) (*Policy, field.ErrorList) {
	var allErrs field.ErrorList
	vpolEnvSet, variablesProvider, err := NewEnv()
	if err != nil {
		return nil, append(allErrs, field.InternalError(nil, fmt.Errorf(compileError, err)))
	}

	env, err := vpolEnvSet.Env(environment.StoredExpressions)
	if err != nil {
		return nil, append(allErrs, field.InternalError(nil, fmt.Errorf(compileError, err)))
	}

	path := field.NewPath("spec")
	spec := policy.GetValidatingPolicySpec()
	// append a place holder error to the errors list to be displayed in case the error list was returned
	allErrs = append(allErrs, field.InternalError(nil, fmt.Errorf(compileError, "failed to compile policy")))

	matchConditions := make([]cel.Program, 0, len(spec.MatchConditions))
	{
		path := path.Child("matchConditions")
		programs, errs := compiler.CompileMatchConditions(path, env, spec.MatchConditions...)
		if errs != nil {
			return nil, append(allErrs, errs...)
		}
		matchConditions = append(matchConditions, programs...)
	}

	variables, errs := compiler.CompileVariables(path.Child("variables"), env, variablesProvider, spec.Variables...)
	if errs != nil {
		return nil, append(allErrs, errs...)
	}

	validations := make([]compiler.Validation, 0, len(spec.Validations))
	{
		path := path.Child("validations")
		for i, rule := range spec.Validations {
			path := path.Index(i)
			program, errs := compiler.CompileValidation(path, env, rule)
			if errs != nil {
				return nil, append(allErrs, errs...)
			}
			validations = append(validations, program)
		}
	}
	auditAnnotations, errs := compiler.CompileAuditAnnotations(path.Child("auditAnnotations"), env, spec.AuditAnnotations...)
	if errs != nil {
		return nil, append(allErrs, errs...)
	}
	return &Policy{
		mode:             policieskyvernoio.EvaluationModeKubernetes,
		failurePolicy:    policy.GetFailurePolicy(false),
		matchConstraints: spec.MatchConstraints,
		matchConditions:  matchConditions,
		variables:        variables,
		validations:      validations,
		auditAnnotations: auditAnnotations,
	}, nil
}
