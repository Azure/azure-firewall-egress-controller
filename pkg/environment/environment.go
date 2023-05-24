// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package environment

import (
	"os"
	"strconv"

	utils "github.com/Azure/azure-firewall-egress-controller/pkg/utils"
)

const (

	// ClientIDVarName is an environment variable which stores the client id provided through user assigned identity
	ClientIDVarName = "AZURE_CLIENT_ID"

	// SubscriptionIDVarName is the name of the FW_POLICY_SUBSCRIPTION_ID
	SubscriptionIDVarName = "FW_POLICY_SUBSCRIPTION_ID"

	// ResourceGroupNameVarName is the name of the FW_POLICY_RESOURCE_GROUP
	ResourceGroupNameVarName = "FW_POLICY_RESOURCE_GROUP"

	// fwPolicyVarName is the name of the FW_POLICY_NAME
	fwPolicyVarName = "FW_POLICY_NAME"

	// The name of your Firewall policy Rule Collection Group
	fwPolicyRuleCollectionGroupvarName = "FW_POLICY_RULE_COLLECTION_GROUP"

	fwPolicyRuleCollectionGroupPriorityVarName = "FW_POLICY_RULE_COLLECTION_GROUP_PRIORITY"

	// fwPolicyResourceID is the name of the FW_POLICY_RESOURCE_ID
	fwPolicyResourceID = "FW_POLICY_RESOURCE_ID"
)

// EnvVariables is a struct storing values for environment variables.
type EnvVariables struct {
	ClientID                            string
	SubscriptionID                      string
	ResourceGroupName                   string
	FwPolicyName                        string
	FwPolicyRuleCollectionGroupName     string
	FwPolicyRuleCollectionGroupPriority int32
	FwPolicyResourceID                  string
}

// GetEnv returns values for defined environment variables for Egress Controller.
func GetEnv() EnvVariables {
	rcgPriority, _ := strconv.ParseInt(os.Getenv(fwPolicyRuleCollectionGroupPriorityVarName), 10, 64)

	env := EnvVariables{
		ClientID:                            os.Getenv(ClientIDVarName),
		SubscriptionID:                      os.Getenv(SubscriptionIDVarName),
		ResourceGroupName:                   os.Getenv(ResourceGroupNameVarName),
		FwPolicyName:                        os.Getenv(fwPolicyVarName),
		FwPolicyRuleCollectionGroupName:     os.Getenv(fwPolicyRuleCollectionGroupvarName),
		FwPolicyRuleCollectionGroupPriority: int32(rcgPriority),
		FwPolicyResourceID:                  os.Getenv(fwPolicyResourceID),
	}

	if env.FwPolicyResourceID != "" {
		subscriptionID, resourceGroupName, firewallPolicyName := utils.ParseResourceID(env.FwPolicyResourceID)
		env.SubscriptionID = string(subscriptionID)
		env.ResourceGroupName = string(resourceGroupName)
		env.FwPolicyName = string(firewallPolicyName)
	}

	return env
}
