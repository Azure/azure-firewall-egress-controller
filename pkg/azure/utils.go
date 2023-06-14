// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package azure

import (
	"reflect"

	azurefirewallrulesv1 "github.com/Azure/azure-firewall-egress-controller/pkg/api/v1"
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

func getSourceAddressesByNodeLabels(k string, v string, nodeList corev1.NodeList) []*string {
	var sourceAddresses []*string
	for _, node := range nodeList.Items {
		if checkIfLabelExists(k, v, node.ObjectMeta.Labels) {
			sourceAddresses = append(sourceAddresses, to.StringPtr(node.Status.Addresses[0].Address))
		}
	}
	return sourceAddresses
}

func checkIfRuleExistsOnNode(node corev1.Node, erulesList azurefirewallrulesv1.AzureFirewallRulesList, newNodeSelector map[string]string, oldNodeSelector map[string]string) bool {
	for _, item := range erulesList.Items {
		for _, egressrule := range item.Spec.EgressRules {
			if egressrule.NodeSelector != nil {
				for _, m := range egressrule.NodeSelector {
					for k, v := range m {
						if checkIfLabelExists(k, v, newNodeSelector) {
							return true
						}
					}
				}
			}
		}
	}
	if !reflect.DeepEqual(newNodeSelector, oldNodeSelector) {
		for _, item := range erulesList.Items {
			for _, egressrule := range item.Spec.EgressRules {
				if egressrule.NodeSelector != nil {
					for _, m := range egressrule.NodeSelector {
						for k, v := range m {
							if checkIfLabelExists(k, v, oldNodeSelector) {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}
