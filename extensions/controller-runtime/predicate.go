// Package controllerruntime provides integration utilities between the
// controller-runtime framework and the SDK's core abstractions.
//
// It defines a generic apiSource that acts as a live, controller-managed
// Source of Kubernetes API objects. This allows the SDK to automatically
// track, reconcile, and serve Kubernetes resources as typed data sources
// within an evaluation engine.
package controllerruntime

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

// apiWithPredicate is a generic implementation of a Kubernetes-backed data source
// with a predicate function called after each reconcile operation.
//
// It's main purpose is deletegating what happens on reconcile to the caller which
// can implement custom logic for object processing.
// apiWithPredicate is not an implementation of the core.Source interface because
// it doesn't store objects it reconciles. Simply hands them off to the predicate function.
//
// Each reconcile events triggers the predicate function with the object's key,
// a pointer to the object, and a boolean indicating whether the object was deleted.
//
// Type parameters:
//
//	API     — the concrete Kubernetes API object type (e.g., v1.ConfigMap)
//	API_PTR — a pointer to API (e.g., *v1.ConfigMap)
type apiWithPredicate[API any, API_PTR api[API]] struct {
	client    client.Client               // Kubernetes client used to Get objects
	predicate func(string, API_PTR, bool) // function to call after a reconcile operation
}

// NewApiSource creates and registers a new controller-runtime managed source
// for a specific Kubernetes API type.
//
// The returned apiSource watches and maintains an in-memory cache of the
// specified resource type. It can be used as a core.Source for engine components.
//
// Type parameters:
//
//	API — a Kubernetes API object type (must satisfy client.Object)
//
// Parameters:
//
//	mgr     — controller-runtime manager used to build/register the controller
//	options — controller options like concurrency, rate limiting, etc.
//
// Returns:
//
//	*apiSource[API] — a live-updating source of API objects
//	error           — if controller setup fails
//
// Example:
//
//	type MyResource v1.ConfigMap
//	src, err := controllerruntime.NewApiSource[*v1.ConfigMap](mgr, controller.Options{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	objs, _ := src.Load(ctx) // snapshot of current ConfigMaps
func NewApiWithPredicate[API any, API_PTR api[API]](name string, mgr ctrl.Manager, options controller.Options, predicate func(string, API_PTR, bool)) (*apiWithPredicate[API, API_PTR], error) {
	provider := new(apiWithPredicate[API, API_PTR])

	// Zero-value API for controller registration
	var api API
	var ptr API_PTR = &api

	builder := ctrl.
		NewControllerManagedBy(mgr).
		For(ptr).
		Named(name).
		WithOptions(options)

	if err := builder.Complete(provider); err != nil {
		return nil, err
	}
	provider.predicate = predicate
	return provider, nil
}

// Reconcile implements the controller-runtime Reconciler interface.
//
// It updates the internal resource map to match the current Kubernetes state
// for a given object key. Deleted objects are removed, created/updated objects
// are stored.
//
// Example reconcile flow:
//   - Receive request for a ConfigMap
//   - Attempt to Get() it from the API
//   - If found: store/update in resources map
//   - If deleted: remove from resources map
func (r *apiWithPredicate[API, API_PTR]) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrl.LoggerFrom(ctx)
	logger.Info("Reconcile triggered", "object", req.String())

	var api API
	var ptr API_PTR = &api

	// Attempt to retrieve the object from the API
	err := r.client.Get(ctx, req.NamespacedName, ptr)
	if errors.IsNotFound(err) {
		r.predicate(req.String(), nil, true)
		return ctrl.Result{}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	r.predicate(req.String(), ptr, false)
	// // Object created or updated — store a copy in cache so we don't retain a pointer to stack
	return ctrl.Result{}, nil
}
