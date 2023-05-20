// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package azure

import (
	n "github.com/Azure/azure-sdk-for-go/services/network/mgmt/2021-03-01/network"

	utils "github.com/Azure/azure-firewall-egress-controller/pkg/utils"
)

func dumpSanitizedJSON(fwRuleCollectionGrpObj *n.FirewallPolicyRuleCollectionGroup) ([]byte, error) {
	jsonConfig, err := fwRuleCollectionGrpObj.MarshalJSON()
	prefix := "--Azure FW config --"
	if err != nil {
		return nil, err
	}

	prettyJSON, err := utils.PrettyJSON(jsonConfig, prefix)

	return prettyJSON, err
}
