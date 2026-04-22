package json

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kyverno/sdk/extensions/cel/utils"
)

type impl struct {
	types.Adapter
}

func (i *impl) unmarshal(json ref.Val, value ref.Val) ref.Val {
	if jsonVal, err := utils.ConvertToNative[Json](json); err != nil {
		return types.WrapErr(err)
	} else if value, err := utils.ConvertToNative[string](value); err != nil {
		return types.WrapErr(err)
	} else {
		if value, err := jsonVal.Unmarshal([]byte(value)); err != nil {
			return types.WrapErr(err)
		} else {
			return i.NativeToValue(value)
		}
	}
}

func (i *impl) marshal(jsonObj ref.Val, value ref.Val) ref.Val {
	if jsonVal, err := utils.ConvertToNative[Json](jsonObj); err != nil {
		return types.WrapErr(err)
	} else if native, err := toJsonNative(value); err != nil {
		return types.WrapErr(err)
	} else {
		if data, err := jsonVal.Marshal(native); err != nil {
			return types.WrapErr(err)
		} else {
			return i.NativeToValue(string(data))
		}
	}
}

// toJsonNative converts a CEL ref.Val to a native Go value
// suitable for JSON marshaling (map, list, or primitive).
func toJsonNative(val ref.Val) (any, error) {
	switch val.Type() {
	case types.MapType:
		return utils.ConvertToNative[map[string]any](val)
	case types.ListType:
		return utils.ConvertToNative[[]any](val)
	default:
		return val.Value(), nil
	}
}
