package controllerruntime

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestApiSource_Load_EmptyInitially(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	src := newApiSource[corev1.ConfigMap](client)
	ctx := context.Background()

	list, err := src.Load(ctx)
	assert.NoError(t, err)
	assert.Empty(t, list)
}

func TestApiSource_Reconcile_ThenLoad_ReturnsObject(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "cm1"},
		Data:       map[string]string{"key": "value"},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm).Build()

	src := newApiSource[corev1.ConfigMap](client)
	ctx := context.Background()

	req := ctrl.Request{}
	req.Namespace = "ns"
	req.Name = "cm1"

	result, err := src.Reconcile(ctx, req)
	assert.NoError(t, err)
	assert.Zero(t, result.RequeueAfter)

	list, err := src.Load(ctx)
	assert.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, "cm1", list[0].GetName())
	assert.Equal(t, "ns", list[0].GetNamespace())
	assert.Equal(t, map[string]string{"key": "value"}, list[0].Data)
}

func TestApiSource_Reconcile_NonexistentKey_DoesNotRemoveExistingEntries(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "cm1"},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm).Build()

	src := newApiSource[corev1.ConfigMap](client)
	ctx := context.Background()

	// Reconcile existing object so it's in the cache
	req1 := ctrl.Request{}
	req1.Namespace = "ns"
	req1.Name = "cm1"
	_, err := src.Reconcile(ctx, req1)
	assert.NoError(t, err)

	list, _ := src.Load(ctx)
	assert.Len(t, list, 1)

	// Reconcile for a different object that doesn't exist - should not affect cache
	req2 := ctrl.Request{}
	req2.Namespace = "ns"
	req2.Name = "nonexistent"
	result, err := src.Reconcile(ctx, req2)
	assert.NoError(t, err)
	assert.Zero(t, result.RequeueAfter)

	// Original object still in cache
	list, _ = src.Load(ctx)
	assert.Len(t, list, 1)
	assert.Equal(t, "cm1", list[0].GetName())
}

// notFoundClient wraps a client and returns NotFound for Get when the key matches.
type notFoundClient struct {
	client.Client
	notFoundNN types.NamespacedName
}

func (c *notFoundClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if key == c.notFoundNN {
		return errors.NewNotFound(corev1.Resource("configmaps"), key.Name)
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func TestApiSource_Reconcile_NotFound_RemovesKeyFromCache(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	// Client that always returns NotFound for ns/cm1 (simulates deleted object)
	baseClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	client := &notFoundClient{Client: baseClient, notFoundNN: types.NamespacedName{Namespace: "ns", Name: "cm1"}}

	src := newApiSource[corev1.ConfigMap](client)
	ctx := context.Background()

	req := ctrl.Request{}
	req.Namespace = "ns"
	req.Name = "cm1"
	result, err := src.Reconcile(ctx, req)
	assert.NoError(t, err)
	assert.Zero(t, result.RequeueAfter)

	list, err := src.Load(ctx)
	assert.NoError(t, err)
	assert.Empty(t, list)
}

func TestApiSource_Load_ReturnsSortedOrder(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	cm1 := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "z"}}
	cm2 := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "a", Name: "a"}}
	cm3 := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "b", Name: "m"}}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm1, cm2, cm3).Build()

	src := newApiSource[corev1.ConfigMap](client)
	ctx := context.Background()

	for _, cm := range []*corev1.ConfigMap{cm1, cm2, cm3} {
		req := ctrl.Request{}
		req.Namespace = cm.Namespace
		req.Name = cm.Name
		_, err := src.Reconcile(ctx, req)
		assert.NoError(t, err)
	}

	list, err := src.Load(ctx)
	assert.NoError(t, err)
	assert.Len(t, list, 3)
	// Keys are sorted: a/a, a/z, b/m
	assert.Equal(t, "a", list[0].GetName())
	assert.Equal(t, "z", list[1].GetName())
	assert.Equal(t, "m", list[2].GetName())
}
