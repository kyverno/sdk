package dpol

import (
	"context"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kyverno/sdk/extensions/cel/compiler"
	"github.com/kyverno/sdk/extensions/cel/utils"
	"go.uber.org/multierr"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/cel/lazy"
)

// Policy is a compiled DeletingPolicy ready for evaluation.
type Policy struct {
	matchConstraints *admissionregistrationv1.MatchResources
	conditions       []cel.Program
	variables        map[string]cel.Program
}

func (p *Policy) MatchConstraints() *admissionregistrationv1.MatchResources {
	return p.matchConstraints
}

// Evaluate returns a non-nil EvaluationResult with Match=true when all conditions pass,
// indicating the object should be deleted. Returns nil when the object does not match.
func (p *Policy) Evaluate(ctx context.Context, object runtime.Object) (*EvaluationResult, error) {
	data, err := prepareData(object)
	if err != nil {
		return nil, err
	}

	dataMap := map[string]any{
		compiler.ObjectKey: data.Object,
	}

	// Variables are resolved lazily and are available to conditions.
	vars := lazy.NewMapValue(compiler.VariablesType)
	dataMap[compiler.VariablesKey] = vars
	for name, variable := range p.variables {
		name, variable := name, variable
		vars.Append(name, func(*lazy.MapValue) ref.Val {
			out, _, err := variable.ContextEval(ctx, dataMap)
			if out != nil {
				return out
			}
			if err != nil {
				return types.WrapErr(err)
			}
			return nil
		})
	}

	match, err := p.evalConditions(ctx, dataMap)
	if err != nil {
		return &EvaluationResult{Error: err}, nil
	}
	return &EvaluationResult{Match: match}, nil
}

func (p *Policy) evalConditions(ctx context.Context, data map[string]any) (bool, error) {
	var errs []error
	for _, condition := range p.conditions {
		out, _, err := condition.ContextEval(ctx, data)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		result, err := utils.ConvertToNative[bool](out)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !result {
			return false, nil
		}
	}
	// On error, default to not deleting (safer than accidentally deleting resources).
	if err := multierr.Combine(errs...); err != nil {
		return false, err
	}
	return true, nil
}
