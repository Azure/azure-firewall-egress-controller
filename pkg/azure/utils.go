// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package controllers

import (
	"github.com/Azure/go-autorest/autorest/to"
	corev1 "k8s.io/api/core/v1"
)

func checkIfLabelExists(k string, v string, m2 map[string]string) bool {
	for k1, v1 := range m2 {
		if k1 == k && v1 == v {
			return true
		}
	}
	return false
}

func unique(arr []string) []string {
	occurred := map[string]bool{}
	result := []string{}
	for e := range arr {
		if occurred[arr[e]] != true {
			occurred[arr[e]] = true
			result = append(result, arr[e])
		}
	}
	return result
}

func checkIfElementsPresentInArray(arr1 []*string, arr2 []*string) bool {
	newElementFound := false
	for _, ele1 := range arr1 {
		found := false
		for _, ele2 := range arr2 {
			if *ele1 == *ele2 {
				found = true
				break
			}
		}
		if found == false {
			newElementFound = true
			break
		}
	}
	return newElementFound
}

func getSourceAddressesByPodLabels(k string, v string, podList corev1.PodList) []*string {
	var sourceAddresses []*string
	for _, pod := range podList.Items {
		if pod.ObjectMeta.Namespace != "kube-system" {
			if pod.Status.Phase == "Running" && checkIfLabelExists(k, v, pod.ObjectMeta.Labels) {
				sourceAddresses = append(sourceAddresses, to.StringPtr(pod.Status.HostIP))
			}
		}
	}
	return sourceAddresses
}

func getSourceAddressesByNodeLabels(k string, v string, nodeList corev1.NodeList) []*string {
	var sourceAddresses []*string
	for _, node := range nodeList.Items {
		if checkIfLabelExists(k, v, node.ObjectMeta.Labels) {
			sourceAddresses = append(sourceAddresses, to.StringPtr(node.Status.Addresses[0].Address))
		}
	}
	return sourceAddresses
}
