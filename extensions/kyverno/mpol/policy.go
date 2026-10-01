package mpol

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/kyverno/sdk/extensions/cel/compiler"
	"go.uber.org/multierr"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	admissionregistrationv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/cel/lazy"
	"k8s.io/apiserver/pkg/cel/mutation"

	"github.com/kyverno/sdk/extensions/cel/utils"
)

// Policy is a compiled MutatingPolicy ready for evaluation.
type Policy struct {
	failurePolicy    admissionregistrationv1.FailurePolicyType
	matchConstraints admissionregistrationv1.MatchResources
	matchConditions  []cel.Program
	variables        map[string]cel.Program
	mutations        []compiledMutation
}

func (p *Policy) Evaluate(
	ctx context.Context,
	attr admission.Attributes,
	request *admissionv1.AdmissionRequest,
	namespace runtime.Object,
) (*EvaluationResult, error) {
	data, err := prepareK8sData(attr, request, namespace)
	if err != nil {
		return nil, err
	}
	return p.evaluateWithData(ctx, data)
}

func (p *Policy) evaluateWithData(
	ctx context.Context,
	data evaluationData,
) (*EvaluationResult, error) {
	dataNew := map[string]any{
		compiler.NamespaceObjectKey: data.Namespace,
		compiler.ObjectKey:          data.Object,
		compiler.OldObjectKey:       data.OldObject,
		compiler.RequestKey:         data.Request,
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

	var patches []Patch
	for i, mutation := range p.mutations {
		out, _, err := mutation.program.ContextEval(ctx, dataNew)
		if err != nil {
			return &EvaluationResult{Matched: true, Error: fmt.Errorf("mutations[%d]: %w", i, err)}, nil
		}

		switch mutation.patchType {
		case admissionregistrationv1alpha1.PatchTypeJSONPatch:
			ops, err := celValueToPatches(out)
			if err != nil {
				return &EvaluationResult{Matched: true, Error: fmt.Errorf("mutations[%d] patch conversion: %w", i, err)}, nil
			}
			patches = append(patches, ops...)
		case admissionregistrationv1alpha1.PatchTypeApplyConfiguration:
			ops, err := celValueToApplyConfigPatches(out)
			if err != nil {
				return &EvaluationResult{Matched: true, Error: fmt.Errorf("mutations[%d] applyConfiguration conversion: %w", i, err)}, nil
			}
			patches = append(patches, ops...)
		}
	}

	return &EvaluationResult{Matched: true, Patches: patches}, nil
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
	if err := multierr.Combine(errs...); err == nil {
		return true, nil
	} else if p.failurePolicy == admissionregistrationv1.Ignore {
		return false, nil
	} else {
		return false, err
	}
}

// celValueToPatches converts a CEL list value to a slice of JSON Patch operations.
// It supports both JSONPatch{op:,path:,value:} struct literals and plain map literals
// of the form {"op":…,"path":…,"value":…}.
func celValueToPatches(val ref.Val) ([]Patch, error) {
	if val == nil {
		return nil, nil
	}
	lv, ok := val.(traits.Lister)
	if !ok {
		return nil, fmt.Errorf("expected list of patch operations, got %T", val)
	}
	size, _ := lv.Size().Value().(int64)
	if size == 0 {
		return nil, nil
	}

	var patches []Patch
	for it := lv.Iterator(); it.HasNext() == types.True; {
		elem := it.Next()
		if jpv, ok := elem.(*mutation.JSONPatchVal); ok {
			// JSONPatch{op:, path:, value:} struct syntax
			p := Patch{Op: jpv.Op, Path: jpv.Path}
			if jpv.Val != nil {
				nv, err := celValToNative(jpv.Val)
				if err != nil {
					return nil, fmt.Errorf("convert JSONPatch value: %w", err)
				}
				p.Value = nv
			}
			patches = append(patches, p)
		} else {
			// Plain map literal {"op":…,"path":…,"value":…} syntax
			native, err := elem.ConvertToNative(reflect.TypeFor[any]())
			if err != nil {
				return nil, fmt.Errorf("convert patch element: %w", err)
			}
			raw, err := json.Marshal(normaliseValue(native))
			if err != nil {
				return nil, fmt.Errorf("marshal patch element: %w", err)
			}
			var p Patch
			if err := json.Unmarshal(raw, &p); err != nil {
				return nil, fmt.Errorf("unmarshal patch element: %w", err)
			}
			patches = append(patches, p)
		}
	}
	return patches, nil
}

// celValToNative recursively converts a CEL ref.Val to a JSON-compatible Go value.
func celValToNative(v ref.Val) (any, error) {
	if v == nil || v == types.NullValue {
		return nil, nil
	}
	switch v.Type() {
	case types.StringType, types.IntType, types.DoubleType, types.BoolType, types.BytesType:
		return v.Value(), nil
	}
	// For maps and lists, use ConvertToNative then normalise.
	if native, err := v.ConvertToNative(reflect.TypeFor[any]()); err == nil {
		return normaliseValue(native), nil
	}
	return normaliseValue(v.Value()), nil
}

// normaliseValue recursively converts map[interface{}]interface{} (produced by CEL ConvertToNative)
// to map[string]any so it can be JSON-encoded.
func normaliseValue(v any) any {
	switch t := v.(type) {
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[fmt.Sprintf("%v", k)] = normaliseValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, elem := range t {
			out[i] = normaliseValue(elem)
		}
		return out
	default:
		return v
	}
}

// celValueToApplyConfigPatches converts a CEL object (ApplyConfiguration) to JSON Patch add/replace ops
// by flattening top-level fields. Nested fields and arrays are set as a whole via a single replace.
func celValueToApplyConfigPatches(val ref.Val) ([]Patch, error) {
	if val == nil {
		return nil, nil
	}
	native, err := val.ConvertToNative(reflect.TypeFor[map[string]any]())
	if err != nil {
		return nil, fmt.Errorf("expected object for applyConfiguration: %w", err)
	}
	obj, ok := native.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected object for applyConfiguration, got %T", native)
	}
	return flattenApplyConfig("", obj), nil
}

// flattenApplyConfig recursively turns a map into JSON Patch replace/add operations.
func flattenApplyConfig(prefix string, obj map[string]any) []Patch {
	var patches []Patch
	for k, v := range obj {
		path := prefix + "/" + jsonPatchEscape(k)
		if nested, ok := v.(map[string]any); ok {
			patches = append(patches, flattenApplyConfig(path, nested)...)
		} else {
			patches = append(patches, Patch{Op: "replace", Path: path, Value: v})
		}
	}
	return patches
}

func jsonPatchEscape(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	s = strings.ReplaceAll(s, "/", "~1")
	return s
}
