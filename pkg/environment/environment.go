// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package environment

import (
	"os"
)

const (

	// ClientIDVarName is an environment variable which stores the client id provided through user assigned identity
	ClientIDVarName = "AZURE_CLIENT_ID"

	// SubscriptionIDVarName is the name of the APPGW_SUBSCRIPTION_ID
	SubscriptionIDVarName = "FW_SUBSCRIPTION_ID"

	// ResourceGroupNameVarName is the name of the APPGW_RESOURCE_GROUP
	ResourceGroupNameVarName = "FW_RESOURCE_GROUP"

	// AppGwNameVarName is the name of the APPGW_NAME
	fwPolicyVarName = "FW_POLICY_NAME"

	// The name of your Firewall policy Rule Collection Group
	fwPolicyRuleCollectionGroupvarName = "FW_POLICY_RULE_COLLECTION_GROUP"
)

// EnvVariables is a struct storing values for environment variables.
type EnvVariables struct {
	ClientID                        string
	SubscriptionID                  string
	ResourceGroupName               string
	FwPolicyName                    string
	FwPolicyRuleCollectionGroupName string
}

// GetEnv returns values for defined environment variables for Ingress Controller.
func GetEnv() EnvVariables {
	env := EnvVariables{
		ClientID:                        os.Getenv(ClientIDVarName),
		SubscriptionID:                  os.Getenv(SubscriptionIDVarName),
		ResourceGroupName:               os.Getenv(ResourceGroupNameVarName),
		FwPolicyName:                    os.Getenv(fwPolicyVarName),
		FwPolicyRuleCollectionGroupName: os.Getenv(fwPolicyRuleCollectionGroupvarName),
	}

	return env
}
