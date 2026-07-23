package json

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kyverno/sdk/extensions/cel/utils"
	"google.golang.org/protobuf/types/known/structpb"
)

// errUnhandledType is returned when a handler cannot process the value.
var errUnhandledType = errors.New("unhandled type")

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
func toJsonNative(value any) (any, error) {
	// Handle ref.Val types first
	if result, err := handleRefVal(value); err != errUnhandledType {
		return result, err
	}

	// Handle known concrete types with fast paths
	if result, err := handleKnownTypes(value); err != errUnhandledType {
		return result, err
	}

	// Fallback: use reflection for truly unknown types
	return handleUnknownTypes(value)
}

// handleRefVal handles conversion of ref.Val types (CEL values).
// Returns errUnhandledType if the value is not a ref.Val.
func handleRefVal(value any) (any, error) {
	if v, ok := value.(ref.Val); ok {
		switch v.Type() {
		case types.NullType:
			return nil, nil
		case types.MapType:
			native, err := utils.ConvertToNative[map[string]any](v)
			if err != nil {
				return nil, fmt.Errorf("json: failed to convert CEL map to native map: %w", err)
			}
			return toJsonNative(native)
		case types.ListType:
			native, err := utils.ConvertToNative[[]any](v)
			if err != nil {
				return nil, fmt.Errorf("json: failed to convert CEL list to native slice: %w", err)
			}
			return toJsonNative(native)
		}
		return toJsonNative(v.Value())
	}
	return nil, errUnhandledType
}

// handleKnownTypes handles common concrete types with fast paths.
// Returns errUnhandledType if the value is not a known type.
func handleKnownTypes(value any) (any, error) {
	switch v := value.(type) {
	case nil:
		return nil, nil
	case structpb.NullValue:
		return nil, nil
	case bool, string,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, uintptr,
		float32, float64,
		[]bool, []string,
		[]int, []int8, []int16, []int32, []int64,
		[]uint, []byte, []uint16, []uint32, []uint64, []uintptr,
		[]float32, []float64:
		return v, nil
	case map[string]any:
		ret := make(map[string]any, len(v))
		for k, val := range v {
			converted, err := toJsonNative(val)
			if err != nil {
				return nil, err
			}
			ret[k] = converted
		}
		return ret, nil
	case []any:
		ret := make([]any, len(v))
		for i, val := range v {
			converted, err := toJsonNative(val)
			if err != nil {
				return nil, err
			}
			ret[i] = converted
		}
		return ret, nil
	}
	return nil, errUnhandledType
}

// handleUnknownTypes handles unknown types using reflection.
// For example:
//   - Native primitives or slice types not listed in fast path
//   - Map keys that are not strings
//   - Aliases and custom types wrapped in ref.Val
func handleUnknownTypes(value any) (any, error) {
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Invalid:
		return nil, nil
	case reflect.Map:
		ret := make(map[string]any, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			key, err := toJsonNative(iter.Key().Interface())
			if err != nil {
				return nil, err
			}
			strKey, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("json: unsupported map key type %T (original key type: %T)", key, iter.Key().Interface())
			}
			val, err := toJsonNative(iter.Value().Interface())
			if err != nil {
				return nil, err
			}
			ret[strKey] = val
		}
		return ret, nil
	case reflect.Slice, reflect.Array:
		ret := make([]any, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			val, err := toJsonNative(rv.Index(i).Interface())
			if err != nil {
				return nil, err
			}
			ret[i] = val
		}
		return ret, nil
	default:
		return value, nil
	}
}
