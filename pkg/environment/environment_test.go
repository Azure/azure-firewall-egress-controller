// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package environment

import (
	"os"
	"testing"
)

func TestGetEnv(t *testing.T) {
	_ = os.Setenv(ClientIDVarName, "ClientIDVarName")
	_ = os.Setenv(SubscriptionIDVarName, "SubscriptionIDVarName")
	_ = os.Setenv(ResourceGroupNameVarName, "ResourceGroupNameVarName")
	_ = os.Setenv(fwPolicyVarName, "fwPolicyVarName")
	_ = os.Setenv(fwPolicyRuleCollectionGroupvarName, "fwPolicyRuleCollectionGroupvarName")
	_ = os.Setenv(fwPolicyRuleCollectionGroupPriorityVarName, "400")

	expected := EnvVariables{
		ClientID:                            "ClientIDVarName",
		SubscriptionID:                      "SubscriptionIDVarName",
		ResourceGroupName:                   "ResourceGroupNameVarName",
		FwPolicyName:                        "fwPolicyVarName",
		FwPolicyRuleCollectionGroupName:     "fwPolicyRuleCollectionGroupvarName",
		FwPolicyRuleCollectionGroupPriority: 400,
	}

	env := GetEnv()

	if expected != env {
		t.Errorf("Expected scope %v, got %v", expected, env)
	}
}
