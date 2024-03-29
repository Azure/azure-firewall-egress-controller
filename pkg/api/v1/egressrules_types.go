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

package v1

import (
	n "github.com/Azure/azure-sdk-for-go/services/network/mgmt/2021-03-01/network"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AzureFirewallRulesSpec defines the desired state of azureFirewallRules
type AzureFirewallRulesSpec struct {
	EgressRules []AzureFirewallEgressRulesSpec `json:"egressRules,omitempty"`
}

type AzureFirewallEgressRulesSpec struct {
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// +kubebuilder:validation:Required
	NodeSelector []map[string]string `json:"nodeSelector"`
	// +kubebuilder:validation:Required
	Rules []AzureFirewallEgressrulesRulesSpec `json:"rules"`
}

type AzureFirewallEgressrulesRulesSpec struct {
	// +kubebuilder:validation:Required
	RuleCollectionName string `json:"ruleCollectionName"`
	// +kubebuilder:validation:Required
	Priority int32 `json:"priority"`
	// +kubebuilder:validation:Required
	RuleName             string   `json:"ruleName"`
	DestinationAddresses []string `json:"destinationAddresses,omitempty"`
	DestinationPorts     []string `json:"destinationPorts,omitempty"`
	DestinationFqdns     []string `json:"destinationFqdns,omitempty"`
	TargetFqdns          []string `json:"targetFqdns,omitempty"`
	TargetUrls           []string `json:"targetUrls,omitempty"`
	// +kubebuilder:validation:Required
	Protocol []string `json:"protocol"`
	// +kubebuilder:validation:Required
	Action n.FirewallPolicyFilterRuleCollectionActionType `json:"action"`
	// +kubebuilder:validation:Required
	RuleType string `json:"ruleType"`
}

// AzureFirewallRulesStatus defines the observed state of azureFirewallRules
type AzureFirewallRulesStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:resource:scope=Cluster
//+kubebuilder:subresource:status

// AzureFirewallRules is the Schema for the azureFirewallRules API
type AzureFirewallRules struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AzureFirewallRulesSpec   `json:"spec,omitempty"`
	Status AzureFirewallRulesStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AzureFirewallRulesList contains a list of azureFirewallRules
type AzureFirewallRulesList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AzureFirewallRules `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AzureFirewallRules{}, &AzureFirewallRulesList{})
}
