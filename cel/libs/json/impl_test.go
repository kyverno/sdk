package json

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/ext"
)

type mockJson struct {
	unmarshalRet any
	unmarshalErr error
	marshalRet   []byte
	marshalErr   error
}

func (m *mockJson) Unmarshal(b []byte) (any, error) {
	return m.unmarshalRet, m.unmarshalErr
}

func (m *mockJson) Marshal(v any) ([]byte, error) {
	if m.marshalRet != nil || m.marshalErr != nil {
		return m.marshalRet, m.marshalErr
	}
	return json.Marshal(v)
}

func TestImplUnmarshal(t *testing.T) {
	env, err := cel.NewEnv(
		ext.NativeTypes(reflect.TypeFor[Json]()),
	)
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}
	adapter := env.CELTypeAdapter()
	i := &impl{adapter}

	type testCase struct {
		name         string
		jsonVal      any
		valueVal     any
		expectErr    bool
		expectResult any
	}

	tests := []testCase{
		{
			name:         "success",
			jsonVal:      Json{&mockJson{unmarshalRet: map[string]any{"foo": "bar"}}},
			valueVal:     `{"foo":"bar"}`,
			expectResult: map[string]any{"foo": "bar"},
		},
		{
			name:      "json convert error",
			jsonVal:   "not a json struct",
			valueVal:  "irrelevant",
			expectErr: true,
		},
		{
			name:      "value convert error",
			jsonVal:   Json{&mockJson{}},
			valueVal:  12345,
			expectErr: true,
		},
		{
			name:      "unmarshal error",
			jsonVal:   Json{&mockJson{unmarshalErr: errors.New("unmarshal failed")}},
			valueVal:  "bad json",
			expectErr: true,
		},
		{
			name:      "json is nil",
			jsonVal:   nil,
			valueVal:  `{"foo":"bar"}`,
			expectErr: true,
		},
		{
			name:      "value is nil",
			jsonVal:   Json{&mockJson{unmarshalRet: map[string]any{"foo": "bar"}}},
			valueVal:  nil,
			expectErr: true,
		},
		{
			name:         "value is empty string",
			jsonVal:      Json{&mockJson{unmarshalRet: map[string]any{}}},
			valueVal:     "",
			expectResult: map[string]any{},
		},
		{
			name:         "json is empty struct",
			jsonVal:      Json{&mockJson{unmarshalRet: map[string]any{}}},
			valueVal:     `{"foo":"bar"}`,
			expectResult: map[string]any{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jsonVal := adapter.NativeToValue(tc.jsonVal)
			valueVal := adapter.NativeToValue(tc.valueVal)
			result := i.unmarshal(jsonVal, valueVal)
			if tc.expectErr {
				if result.Type() != types.ErrType {
					t.Errorf("expected error type, got %v", result.Type())
				}
			} else {
				got, err := result.ConvertToNative(reflect.TypeOf(tc.expectResult))
				if err != nil {
					t.Fatalf("unexpected conversion error: %v", err)
				}
				if !reflect.DeepEqual(got, tc.expectResult) {
					t.Errorf("expected result %v, got %v", tc.expectResult, got)
				}
			}
		})
	}
}

func TestImplMarshal(t *testing.T) {
	env, err := cel.NewEnv(
		ext.NativeTypes(reflect.TypeFor[Json]()),
	)
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}
	adapter := env.CELTypeAdapter()
	i := &impl{adapter}

	jsonInstance := Json{&JsonImpl{}}

	type testCase struct {
		name         string
		jsonVal      any
		inputVal     any
		expectErr    bool
		expectResult string
	}

	tests := []testCase{
		{
			name:         "marshal map",
			jsonVal:      jsonInstance,
			inputVal:     map[string]any{"foo": "bar"},
			expectResult: `{"foo":"bar"}`,
		},
		{
			name:         "marshal list",
			jsonVal:      jsonInstance,
			inputVal:     []any{"a", "b", "c"},
			expectResult: `["a","b","c"]`,
		},
		{
			name:         "marshal string",
			jsonVal:      jsonInstance,
			inputVal:     "hello",
			expectResult: `"hello"`,
		},
		{
			name:         "marshal int",
			jsonVal:      jsonInstance,
			inputVal:     int64(42),
			expectResult: `42`,
		},
		{
			name:         "marshal float",
			jsonVal:      jsonInstance,
			inputVal:     3.14,
			expectResult: `3.14`,
		},
		{
			name:         "marshal bool",
			jsonVal:      jsonInstance,
			inputVal:     true,
			expectResult: `true`,
		},
		{
			name:      "json convert error",
			jsonVal:   "not a json struct",
			inputVal:  "irrelevant",
			expectErr: true,
		},
		{
			name:      "marshal error",
			jsonVal:   Json{&mockJson{marshalErr: errors.New("marshal failed")}},
			inputVal:  "some value",
			expectErr: true,
		},
		{
			name:         "marshal empty map",
			jsonVal:      jsonInstance,
			inputVal:     map[string]any{},
			expectResult: `{}`,
		},
		{
			name:         "marshal empty list",
			jsonVal:      jsonInstance,
			inputVal:     []any{},
			expectResult: `[]`,
		},
		{
			name:         "marshal nested object",
			jsonVal:      jsonInstance,
			inputVal:     map[string]any{"outer": map[string]any{"inner": "value"}},
			expectResult: `{"outer":{"inner":"value"}}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jsonVal := adapter.NativeToValue(tc.jsonVal)
			inputVal := adapter.NativeToValue(tc.inputVal)
			result := i.marshal(jsonVal, inputVal)
			if tc.expectErr {
				if result.Type() != types.ErrType {
					t.Errorf("expected error type, got %v", result.Type())
				}
			} else {
				got, err := result.ConvertToNative(reflect.TypeOf(""))
				if err != nil {
					t.Fatalf("unexpected conversion error: %v", err)
				}
				if got.(string) != tc.expectResult {
					t.Errorf("expected %q, got %q", tc.expectResult, got)
				}
			}
		})
	}
}

func TestMarshalCELIntegration(t *testing.T) {
	env, err := cel.NewEnv(
		Lib(&JsonImpl{}, Latest()),
	)
	if err != nil {
		t.Fatalf("failed to create CEL environment: %v", err)
	}

	tests := []struct {
		name       string
		expr       string
		expectJSON string
	}{
		{
			name:       "marshal map literal",
			expr:       `json.marshal({"key": "value"})`,
			expectJSON: `{"key":"value"}`,
		},
		{
			name:       "marshal list literal",
			expr:       `json.marshal([1, 2, 3])`,
			expectJSON: `[1,2,3]`,
		},
		{
			name:       "marshal string",
			expr:       `json.marshal("hello")`,
			expectJSON: `"hello"`,
		},
		{
			name:       "marshal int",
			expr:       `json.marshal(42)`,
			expectJSON: `42`,
		},
		{
			name:       "marshal bool",
			expr:       `json.marshal(true)`,
			expectJSON: `true`,
		},
		{
			name:       "roundtrip unmarshal then marshal",
			expr:       `json.marshal(json.unmarshal("{\"a\":\"b\"}"))`,
			expectJSON: `{"a":"b"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ast, issues := env.Compile(tc.expr)
			if issues != nil && issues.Err() != nil {
				t.Fatalf("compile error: %v", issues.Err())
			}
			prog, err := env.Program(ast)
			if err != nil {
				t.Fatalf("program error: %v", err)
			}
			out, _, err := prog.Eval(map[string]any{})
			if err != nil {
				t.Fatalf("eval error: %v", err)
			}
			got := out.Value().(string)
			if got != tc.expectJSON {
				t.Errorf("expected %q, got %q", tc.expectJSON, got)
			}
		})
	}
}
