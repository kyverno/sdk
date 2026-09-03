package gpol

import (
	"context"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kyverno/sdk/extensions/cel/compiler"
	"github.com/kyverno/sdk/extensions/cel/libs/generator"
	"github.com/kyverno/sdk/extensions/cel/utils"
	"go.uber.org/multierr"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/cel/lazy"
)

// Policy is a compiled GeneratingPolicy ready for evaluation.
type Policy struct {
	matchConstraints *admissionregistrationv1.MatchResources
	matchConditions  []cel.Program
	variables        map[string]cel.Program
	generations      []cel.Program
}

func (p *Policy) MatchConstraints() *admissionregistrationv1.MatchResources {
	return p.matchConstraints
}

// Evaluate runs the policy against an admission request.
// genCtx is the generator context used to create resources; it is injected per-evaluation
// so that resource creation uses the correct Kubernetes client and dry-run flag.
// Returns nil when match conditions are not met.
func (p *Policy) Evaluate(
	ctx context.Context,
	attr admission.Attributes,
	request *admissionv1.AdmissionRequest,
	namespace runtime.Object,
	genCtx generator.ContextInterface,
) (*EvaluationResult, error) {
	data, err := prepareK8sData(attr, request, namespace)
	if err != nil {
		return nil, err
	}
	return p.evaluateWithData(ctx, data, genCtx)
}

func (p *Policy) evaluateWithData(
	ctx context.Context,
	data evaluationData,
	genCtx generator.ContextInterface,
) (*EvaluationResult, error) {
	dataNew := map[string]any{
		compiler.NamespaceObjectKey: data.Namespace,
		compiler.ObjectKey:          data.Object,
		compiler.OldObjectKey:       data.OldObject,
		compiler.RequestKey:         data.Request,
		// Override the compiled-in nil generator global with the real per-evaluation context.
		compiler.GeneratorKey: generator.Context{ContextInterface: genCtx},
	}

	match, err := p.match(ctx, dataNew, p.matchConditions)
	if err != nil {
		return nil, err
	}
	if !match {
		return nil, nil
	}

	vars := lazy.NewMapValue(compiler.VariablesType)
	dataNew[compiler.VariablesKey] = vars
	for name, variable := range p.variables {
		name, variable := name, variable
		vars.Append(name, func(*lazy.MapValue) ref.Val {
			out, _, err := variable.ContextEval(ctx, dataNew)
			if out != nil {
				return out
			}
			if err != nil {
				return types.WrapErr(err)
			}
			return nil
		})
	}

	for i, gen := range p.generations {
		out, _, err := gen.ContextEval(ctx, dataNew)
		if err != nil {
			return &EvaluationResult{Matched: true, Error: fmt.Errorf("generate[%d]: %w", i, err)}, nil
		}
		if ok, convErr := utils.ConvertToNative[bool](out); convErr != nil {
			return &EvaluationResult{Matched: true, Error: fmt.Errorf("generate[%d] result: %w", i, convErr)}, nil
		} else if !ok {
			return &EvaluationResult{Matched: true, Error: fmt.Errorf("generate[%d]: expression returned false", i)}, nil
		}
	}

	return &EvaluationResult{Matched: true}, nil
}

func (p *Policy) match(
	ctx context.Context,
	data map[string]any,
	matchConditions []cel.Program,
) (bool, error) {
	var errs []error
	for _, mc := range matchConditions {
		out, _, err := mc.ContextEval(ctx, data)
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
	if err := multierr.Combine(errs...); err != nil {
		// FailurePolicy for GeneratingPolicy is always Ignore.
		return false, nil
	}
	return true, nil
}
