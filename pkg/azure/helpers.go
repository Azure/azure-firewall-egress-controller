// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package azure

import (
	"bytes"

	n "github.com/Azure/azure-sdk-for-go/services/network/mgmt/2021-03-01/network"
	"k8s.io/klog/v2"

	utils "github.com/Azure/azure-firewall-egress-controller/pkg/utils"
)

func dumpSanitizedJSON(fwRuleCollectionGrp *n.FirewallPolicyRuleCollectionGroup) ([]byte, error) {
	jsonConfig, err := fwRuleCollectionGrp.MarshalJSON()
	prefix := "--Azure FW config --"
	if err != nil {
		return nil, err
	}

	prettyJSON, err := utils.PrettyJSON(jsonConfig, prefix)

	return prettyJSON, err
}

func (az *azClient) configIsSame(fwRuleCollectionGrp *n.FirewallPolicyRuleCollectionGroup) bool {
	if az.configCache == nil {
		return false
	}

	jsonConfig, err := fwRuleCollectionGrp.MarshalJSON()
	if err != nil {
		klog.Error("Could not marshal fw config.")
	}
	klog.Info("input state = ", string(jsonConfig))
	klog.Info("cached state = ", string(*az.configCache))

	// The result will be 0 if a==b, -1 if a < b, and +1 if a > b.
	return az.configCache != nil && bytes.Compare(*az.configCache, jsonConfig) == 0
}

func (az *azClient) updateCache(fwRuleCollectionGrp *n.FirewallPolicyRuleCollectionGroup) {
	jsonConfig, err := fwRuleCollectionGrp.MarshalJSON()
	if err != nil {
		klog.Error("Could not marshal fw config to update cache; Wiping cache.", err)
		az.configCache = nil
		return
	}
	*az.configCache = jsonConfig
}
