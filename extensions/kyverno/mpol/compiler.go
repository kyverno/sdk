package mpol

import (
	"fmt"

	"github.com/google/cel-go/cel"
	policiesv1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
	"github.com/kyverno/sdk/extensions/cel/compiler"
	admissionregistrationv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/cel/environment"
)

var compileError = "mutating policy compiler " + mpolCompilerVersion.String() + " error: %s"

// compiledMutation holds a compiled mutation program alongside its patch type.
type compiledMutation struct {
	patchType admissionregistrationv1alpha1.PatchType
	program   cel.Program
}

// Compiler compiles a MutatingPolicyLike into a Policy ready for evaluation.
type Compiler interface {
	Compile(policy policiesv1.MutatingPolicyLike) (*Policy, field.ErrorList)
}

func NewCompiler() Compiler {
	return &compilerImpl{}
}

type compilerImpl struct{}

func (c *compilerImpl) Compile(policy policiesv1.MutatingPolicyLike) (*Policy, field.ErrorList) {
	var allErrs field.ErrorList
	mpolEnvSet, variablesProvider, err := NewEnv()
	if err != nil {
		return nil, append(allErrs, field.InternalError(nil, fmt.Errorf(compileError, err)))
	}

	env, err := mpolEnvSet.Env(environment.StoredExpressions)
	if err != nil {
		return nil, append(allErrs, field.InternalError(nil, fmt.Errorf(compileError, err)))
	}

	path := field.NewPath("spec")
	spec := policy.GetSpec()
	allErrs = append(allErrs, field.InternalError(nil, fmt.Errorf(compileError, "failed to compile policy")))

	matchConditions, errs := compiler.CompileMatchConditions(path.Child("matchConditions"), env, spec.MatchConditions...)
	if errs != nil {
		return nil, append(allErrs, errs...)
	}

	variables, errs := compiler.CompileVariables(path.Child("variables"), env, variablesProvider, spec.Variables...)
	if errs != nil {
		return nil, append(allErrs, errs...)
	}

	mutations := make([]compiledMutation, 0, len(spec.Mutations))
	{
		path := path.Child("mutations")
		for i, mutation := range spec.Mutations {
			path := path.Index(i)
			switch mutation.PatchType {
			case admissionregistrationv1alpha1.PatchTypeJSONPatch:
				if mutation.JSONPatch == nil || mutation.JSONPatch.Expression == "" {
					continue
				}
				expr := mutation.JSONPatch.Expression
				ast, issues := env.Compile(expr)
				if err := issues.Err(); err != nil {
					return nil, append(allErrs, field.Invalid(path.Child("jsonPatch", "expression"), expr, err.Error()))
				}
				prog, err := env.Program(ast)
				if err != nil {
					return nil, append(allErrs, field.Invalid(path.Child("jsonPatch", "expression"), expr, err.Error()))
				}
				mutations = append(mutations, compiledMutation{
					patchType: admissionregistrationv1alpha1.PatchTypeJSONPatch,
					program:   prog,
				})
			case admissionregistrationv1alpha1.PatchTypeApplyConfiguration:
				if mutation.ApplyConfiguration == nil || mutation.ApplyConfiguration.Expression == "" {
					continue
				}
				expr := mutation.ApplyConfiguration.Expression
				ast, issues := env.Compile(expr)
				if err := issues.Err(); err != nil {
					return nil, append(allErrs, field.Invalid(path.Child("applyConfiguration", "expression"), expr, err.Error()))
				}
				prog, err := env.Program(ast)
				if err != nil {
					return nil, append(allErrs, field.Invalid(path.Child("applyConfiguration", "expression"), expr, err.Error()))
				}
				mutations = append(mutations, compiledMutation{
					patchType: admissionregistrationv1alpha1.PatchTypeApplyConfiguration,
					program:   prog,
				})
			default:
				return nil, append(allErrs, field.Invalid(path.Child("patchType"), mutation.PatchType, "unknown patchType"))
			}
		}
	}

	return &Policy{
		failurePolicy:    policy.GetFailurePolicy(false),
		matchConstraints: policy.GetMatchConstraints(),
		matchConditions:  matchConditions,
		variables:        variables,
		mutations:        mutations,
	}, nil
}
