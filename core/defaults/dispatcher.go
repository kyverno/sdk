package defaults

import (
	"github.com/kyverno/sdk/core"
	"github.com/kyverno/sdk/core/breakers"
	"github.com/kyverno/sdk/core/dispatchers"
)

func Dispatcher[
	POLICY any,
	DATA any,
	IN any,
	OUT any,
](
	evaluator core.EvaluatorFactory[POLICY, DATA, IN, OUT],
) core.DispatcherFactory[POLICY, DATA, IN, OUT] {
	return dispatchers.Sequential(
		evaluator,
		breakers.NeverFactory[POLICY, DATA, IN, OUT](),
	)
}
