/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"reflect"

	egressv1 "github.com/Azure/azure-firewall-egress-controller/pkg/api/v1"
	a "github.com/Azure/azure-firewall-egress-controller/pkg/azure"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// EgressrulesReconciler reconciles a Egressrules object
type EgressrulesReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	AzClient a.AzClient
}

//+kubebuilder:rbac:groups=egress.azure-firewall-egress-controller.io,resources=egressrules,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=egress.azure-firewall-egress-controller.io,resources=egressrules/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=egress.azure-firewall-egress-controller.io,resources=egressrules/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=nodes,verbs=get;watch;list
//+kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=nodes/status,verbs=get;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Egressrules object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.1/pkg/reconcile
func (r *EgressrulesReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	node := &corev1.Node{}
	err := r.Get(ctx, req.NamespacedName, node)

	if (err != nil && req.NamespacedName.Namespace != "kube-system") || (err == nil && !a.CheckIfNodeNotReady(node)) {
		go r.AzClient.UpdateFirewallPolicy(ctx, req)
	} else if a.CheckIfNodeNotReady(node) {
		go r.AzClient.AddTaints(ctx, req)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *EgressrulesReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&egressv1.Egressrules{}).
		Watches(&source.Kind{Type: &corev1.Node{}}, &handler.EnqueueRequestForObject{}).
		WithEventFilter(predicate.Funcs{
			UpdateFunc: func(e event.UpdateEvent) bool {
				if _, ok := e.ObjectNew.(*corev1.Node); ok {
					oldObj := e.ObjectOld.(*corev1.Node)
					newObj := e.ObjectNew.(*corev1.Node)

					labelChanged := !reflect.DeepEqual(oldObj.GetLabels(), newObj.GetLabels())
					ipChanged := oldObj.Status.Addresses[0].Address != newObj.Status.Addresses[0].Address
					// Only trigger the reconciler if a specific field has changed.
					return labelChanged || ipChanged
				}
				return true
			},
		}).
		Complete(r)
}
