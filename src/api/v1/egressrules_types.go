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

// EgressrulesSpec defines the desired state of Egressrules
type EgressrulesSpec struct {
	RuleCollectionName   string                                         `json:"ruleCollectionName,omitempty"`
	SourceAddress        []string                                       `json:"sourceAddress,omitempty"`
	NodeSelector         []map[string]string                            `json:"nodeSelector,omitempty"`
	PodSelector          []map[string]string                            `json:"podSelector,omitempty"`
	DestinationAddresses []string                                       `json:"destinationAddresses,omitempty"`
	DestinationPorts     []string                                       `json:"destinationPorts,omitempty"`
	DestinationFqdns     []string                                       `json:"destinationFqdns,omitempty"`
	TargetFqdns          []string                                       `json:"targetFqdns,omitempty"`
	TargetUrls           []string                                       `json:"targetUrls,omitempty"`
	Protocol             []string                                       `json:"protocol,omitempty"`
	Action               n.FirewallPolicyFilterRuleCollectionActionType `json:"action,omitempty"`
	RuleType             string                                         `json:"ruleType,omitempty"`
}

// EgressrulesStatus defines the observed state of Egressrules
type EgressrulesStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Egressrules is the Schema for the egressrules API
type Egressrules struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EgressrulesSpec   `json:"spec,omitempty"`
	Status EgressrulesStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// EgressrulesList contains a list of Egressrules
type EgressrulesList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Egressrules `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Egressrules{}, &EgressrulesList{})
}
