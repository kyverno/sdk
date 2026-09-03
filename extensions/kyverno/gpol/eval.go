package gpol

import (
	"fmt"

	"github.com/kyverno/sdk/extensions/cel/utils"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
)

// EvaluationResult is the outcome of evaluating a GeneratingPolicy against an admission request.
// When Matched is false the policy's match conditions were not met and no generation was attempted.
type EvaluationResult struct {
	Matched bool
	Error   error
}

type evaluationData struct {
	Namespace any
	Object    any
	OldObject any
	Request   any
}

func prepareK8sData(
	attr admission.Attributes,
	request *admissionv1.AdmissionRequest,
	namespace runtime.Object,
) (evaluationData, error) {
	if attr == nil {
		return evaluationData{}, fmt.Errorf("cannot evaluate generating policy without admission attributes")
	}
	namespaceVal, err := utils.ObjectToResolveVal(namespace)
	if err != nil {
		return evaluationData{}, fmt.Errorf("failed to prepare namespace variable: %w", err)
	}
	objectVal, err := utils.ObjectToResolveVal(attr.GetObject())
	if err != nil {
		return evaluationData{}, fmt.Errorf("failed to prepare object variable: %w", err)
	}
	oldObjectVal, err := utils.ObjectToResolveVal(attr.GetOldObject())
	if err != nil {
		return evaluationData{}, fmt.Errorf("failed to prepare oldObject variable: %w", err)
	}
	requestVal, err := utils.ConvertObjectToUnstructured(request)
	if err != nil {
		return evaluationData{}, fmt.Errorf("failed to prepare request variable: %w", err)
	}
	return evaluationData{
		Namespace: namespaceVal,
		Object:    objectVal,
		OldObject: oldObjectVal,
		Request:   requestVal.Object,
	}, nil
}
