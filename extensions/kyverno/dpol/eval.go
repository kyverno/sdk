package dpol

import (
	"fmt"

	"github.com/kyverno/sdk/extensions/cel/utils"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/cel/lazy"
)

// EvaluationResult is the outcome of evaluating a DeletingPolicy against a single object.
// Match is true when all conditions passed and the object should be deleted.
type EvaluationResult struct {
	Match bool
	Error error
}

type evaluationData struct {
	Object    any
	Variables *lazy.MapValue
}

func prepareData(object runtime.Object) (evaluationData, error) {
	objectVal, err := utils.ObjectToResolveVal(object)
	if err != nil {
		return evaluationData{}, fmt.Errorf("failed to prepare object variable for evaluation: %w", err)
	}
	return evaluationData{Object: objectVal}, nil
}
