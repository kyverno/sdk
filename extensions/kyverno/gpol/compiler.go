package gpol

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	policiesv1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
	"github.com/kyverno/sdk/extensions/cel/compiler"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/cel/environment"
)

var compileError = "generating policy compiler " + gpolCompilerVersion.String() + " error: %s"

// Compiler compiles a GeneratingPolicyLike into a Policy ready for evaluation.
type Compiler interface {
	Compile(policy policiesv1.GeneratingPolicyLike) (*Policy, field.ErrorList)
}

func NewCompiler() Compiler {
	return &compilerImpl{}
}

type compilerImpl struct{}

func (c *compilerImpl) Compile(policy policiesv1.GeneratingPolicyLike) (*Policy, field.ErrorList) {
	var allErrs field.ErrorList
	gpolEnvSet, variablesProvider, err := NewEnv()
	if err != nil {
		return nil, append(allErrs, field.InternalError(nil, fmt.Errorf(compileError, err)))
	}

	env, err := gpolEnvSet.Env(environment.StoredExpressions)
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

	generations := make([]cel.Program, 0, len(spec.Generation))
	{
		path := path.Child("generate")
		for i, gen := range spec.Generation {
			path := path.Index(i).Child("expression")
			if gen.Expression == "" {
				continue
			}
			ast, issues := env.Compile(gen.Expression)
			if err := issues.Err(); err != nil {
				return nil, append(allErrs, field.Invalid(path, gen.Expression, err.Error()))
			}
			if !ast.OutputType().IsExactType(types.BoolType) {
				msg := fmt.Sprintf("output is expected to be of type %s", types.BoolType.TypeName())
				return nil, append(allErrs, field.Invalid(path, gen.Expression, msg))
			}
			prog, err := env.Program(ast)
			if err != nil {
				return nil, append(allErrs, field.Invalid(path, gen.Expression, err.Error()))
			}
			generations = append(generations, prog)
		}
	}

	return &Policy{
		matchConstraints: spec.MatchConstraints,
		matchConditions:  matchConditions,
		variables:        variables,
		generations:      generations,
	}, nil
}
