// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package azure

import (
	"context"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	a "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var taint = corev1.Taint{
	Key:    "azure-firewall-policy",
	Value:  "update-pending",
	Effect: corev1.TaintEffectNoSchedule,
}

func (az *azClient) AddTaints(ctx context.Context, req ctrl.Request) {
	node := &corev1.Node{}
	if err := az.client.Get(ctx, req.NamespacedName, node); err != nil {
		klog.Error(err, "unable to fetch Node")
	}
	if !CheckIfTaintExists(node) {
		patch := client.MergeFrom(node.DeepCopy())
		node.Spec.Taints = append(node.Spec.Taints, taint)
		err := az.client.Patch(ctx, node, patch)
		if err == nil {
			klog.Info("Taints added on node: ", node.Name)
		} else {
			klog.Info("Error adding the taints", err)
		}
	}
}

func (az *azClient) RemoveTaints(ctx context.Context, node *corev1.Node) {
	if CheckIfTaintExists(node) {
		var updatedTaints []corev1.Taint
		for _, t := range node.Spec.Taints {
			if t.Key != taint.Key {
				updatedTaints = append(updatedTaints, t)
			}
		}

		patch := client.MergeFrom(node.DeepCopy())
		node.Spec.Taints = updatedTaints
		err := az.client.Patch(ctx, node, patch)
		if err == nil {
			klog.Info("Taints removed on node: ", node.Name)
		} else {
			klog.Info("Error removing the taints", err)
		}
	}
}

func (az *azClient) WaitForNodeIpGroupUpdate(ctx context.Context, nodesWithFwTaint []*corev1.Node, pollers map[string]*runtime.Poller[a.IPGroupsClientCreateOrUpdateResponse]) {
	var wg sync.WaitGroup
	for _, poller := range pollers {
		wg.Add(1)
		go func(poller *runtime.Poller[a.IPGroupsClientCreateOrUpdateResponse]) {
			_, err := poller.PollUntilDone(ctx, nil)
			if err != nil {
				klog.Error("failed to pull the result: %v", err)
			}
			defer wg.Done()
		}(poller)
	}
	wg.Wait()
	for _, node := range nodesWithFwTaint {
		az.RemoveTaints(ctx, node)
	}
}

func CheckIfTaintExists(node *corev1.Node) bool {
	for _, t := range node.Spec.Taints {
		if t.Key == taint.Key && t.Effect == taint.Effect {
			return true
		}
	}
	return false
}

func CheckIfNodeNotReady(node *corev1.Node) bool {
	for _, t := range node.Spec.Taints {
		if (t.Key == "node.cloudprovider.kubernetes.io/uninitialized" || t.Key == "node.kubernetes.io/not-ready") && t.Effect == corev1.TaintEffectNoSchedule {
			return true
		}
	}
	return false
}
