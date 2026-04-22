package utils

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestConvertToNative(t *testing.T) {
	t.Run("bool", func(t *testing.T) {
		got, err := ConvertToNative[bool](types.False)
		assert.NoError(t, err)
		assert.False(t, got)
		got, err = ConvertToNative[bool](types.True)
		assert.NoError(t, err)
		assert.True(t, got)
		_, err = ConvertToNative[bool](types.String("false"))
		assert.Error(t, err)
	})
	t.Run("string", func(t *testing.T) {
		got, err := ConvertToNative[string](types.String("hello"))
		assert.NoError(t, err)
		assert.Equal(t, "hello", got)
	})
	t.Run("int", func(t *testing.T) {
		got, err := ConvertToNative[int](types.Int(42))
		assert.NoError(t, err)
		assert.Equal(t, 42, got)
		_, err = ConvertToNative[int](types.True)
		assert.Error(t, err)
	})
	t.Run("int64", func(t *testing.T) {
		got, err := ConvertToNative[int64](types.Int(1 << 40))
		assert.NoError(t, err)
		assert.Equal(t, int64(1<<40), got)
	})
	t.Run("float64", func(t *testing.T) {
		got, err := ConvertToNative[float64](types.Double(3.14))
		assert.NoError(t, err)
		assert.Equal(t, 3.14, got)
	})
}

func TestConvertObjectToUnstructured(t *testing.T) {
	tests := []struct {
		name    string
		obj     any
		want    *unstructured.Unstructured
		wantErr bool
	}{{
		name: "nil",
		obj:  nil,
		want: &unstructured.Unstructured{},
	}, {
		name: "error",
		obj: map[string]string{
			"foo": "bar",
		},
		wantErr: true,
	}, {
		name: "ok",
		obj: &corev1.Namespace{
			TypeMeta: metav1.TypeMeta{
				APIVersion: corev1.SchemeGroupVersion.String(),
				Kind:       "Namespace",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "foo",
			},
		},
		want: &unstructured.Unstructured{
			Object: map[string]any{
				"apiVersion": "v1",
				"kind":       "Namespace",
				"metadata": map[string]any{
					"name": "foo",
				},
				"spec":   map[string]any{},
				"status": map[string]any{},
			},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertObjectToUnstructured(tt.obj)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestObjectToResolveVal(t *testing.T) {
	tests := []struct {
		name    string
		obj     runtime.Object
		want    any
		wantErr bool
	}{{
		name:    "nil",
		obj:     nil,
		want:    nil,
		wantErr: false,
	}, {
		name: "namespace",
		obj: &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test",
			},
		},
		want: map[string]any{
			"metadata": map[string]any{
				"name": "test",
			},
			"spec":   map[string]any{},
			"status": map[string]any{},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ObjectToResolveVal(tt.obj)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestGetValue(t *testing.T) {
	tests := []struct {
		name    string
		data    any
		want    map[string]any
		wantErr bool
	}{{
		name: "nil",
	}, {
		name: "namespace",
		data: &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test",
			},
		},
		want: map[string]any{
			"metadata": map[string]any{
				"name": "test",
			},
			"spec":   map[string]any{},
			"status": map[string]any{},
		},
	}, {
		name:    "error",
		data:    func() {},
		wantErr: true,
	}, {
		name: "map",
		data: map[string]any{
			"key1": "value1",
			"key2": 42,
		},
		want: map[string]any{
			"key1": "value1",
			"key2": float64(42),
		},
	}, {
		name:    "array at top level",
		data:    []string{"a", "b", "c"},
		want:    nil,
		wantErr: true,
	}, {
		name: "struct with nested fields",
		data: struct {
			Name string
			Data map[string]any
		}{
			Name: "nested",
			Data: map[string]any{
				"inner": "value",
			},
		},
		want: map[string]any{
			"Name": "nested",
			"Data": map[string]any{
				"inner": "value",
			},
		},
	}, {
		name: "struct",
		data: struct {
			Foo string `json:"foo"`
		}{
			Foo: "bar",
		},
		want: map[string]any{
			"foo": "bar",
		},
	}, {
		name: "map",
		data: map[string]any{
			"foo": "bar",
		},
		want: map[string]any{
			"foo": "bar",
		},
	}, {
		name: "unstructured",
		data: &unstructured.Unstructured{
			Object: map[string]any{
				"apiVersion": "v1",
				"kind":       "Namespace",
				"metadata": map[string]any{
					"name": "foo",
				},
				"spec":   map[string]any{},
				"status": map[string]any{},
			},
		},
		want: map[string]any{
			"apiVersion": "v1",
			"kind":       "Namespace",
			"metadata": map[string]any{
				"name": "foo",
			},
			"spec":   map[string]any{},
			"status": map[string]any{},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetValue(tt.data)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
