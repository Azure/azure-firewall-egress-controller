// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package azure

import (
	"strconv"
	"strings"

	egressv1 "github.com/Azure/azure-firewall-egress-controller/pkg/api/v1"
	n "github.com/Azure/azure-sdk-for-go/services/network/mgmt/2021-03-01/network"
	"github.com/Azure/go-autorest/autorest/to"
)

func BuildFirewallConfig(erulesList egressv1.EgressrulesList, erulesSourceAddresses map[string][]string) *[]n.BasicFirewallPolicyRuleCollection {
	var ruleCollections []n.BasicFirewallPolicyRuleCollection

	for _, erule := range erulesList.Items {
		if len(erulesSourceAddresses[erule.Name]) != 0 {
			if len(ruleCollections) == 0 || NotFoundRuleCollection(erule, ruleCollections) {
				ruleCollection := BuildRuleCollection(erule, erulesSourceAddresses)
				ruleCollections = append(ruleCollections, ruleCollection)
			} else {
				for i := 0; i < len(ruleCollections); i++ {
					ruleCollection := ruleCollections[i].(*n.FirewallPolicyFilterRuleCollection)
					if erule.Spec.RuleCollectionName == *ruleCollection.Name {
						rules := *ruleCollection.Rules
						rule := GetRule(erule, erulesSourceAddresses)
						rules = append(rules, rule)
						ruleCollection.Rules = &rules
					}
				}
			}
		}

	}
	return &ruleCollections
}

func NotFoundRuleCollection(erule egressv1.Egressrules, ruleCollections []n.BasicFirewallPolicyRuleCollection) bool {
	for i := 0; i < len(ruleCollections); i++ {
		ruleCollection := ruleCollections[i].(*n.FirewallPolicyFilterRuleCollection)
		if erule.Spec.RuleCollectionName == *ruleCollection.Name {
			return false
		}
	}
	return true
}

func BuildRuleCollection(erule egressv1.Egressrules, erulesSourceAddresses map[string][]string) n.BasicFirewallPolicyRuleCollection {
	var priority int32
	if erule.Spec.Action == "Allow" {
		if erule.Spec.RuleType == "Application" {
			priority = 210
		} else {
			priority = 110
		}
	} else {
		if erule.Spec.RuleType == "Application" {
			priority = 200
		} else {
			priority = 100
		}
	}

	ruleCollection := &n.FirewallPolicyFilterRuleCollection{
		Name:               to.StringPtr(erule.Spec.RuleCollectionName),
		Action:             BuildAction(erule.Spec.Action),
		Priority:           &priority,
		RuleCollectionType: GetRuleCollectionType(erule.Spec.RuleType),
		Rules:              BuildRules(erule, erulesSourceAddresses),
	}
	return ruleCollection
}

func BuildRules(erule egressv1.Egressrules, erulesSourceAddresses map[string][]string) *[]n.BasicFirewallPolicyRule {
	var rules []n.BasicFirewallPolicyRule
	rule := GetRule(erule, erulesSourceAddresses)
	rules = append(rules, rule)
	return &rules
}

func GetRule(erule egressv1.Egressrules, erulesSourceAddresses map[string][]string) n.BasicFirewallPolicyRule {

	sourceAddresses := erulesSourceAddresses[erule.Name]
	var rule n.BasicFirewallPolicyRule

	if erule.Spec.RuleType == "Application" {
		targetFqdns := []string{}
		targetUrls := []string{}
		var terminateTLS = false
		destinationAddresses := []string{}

		if erule.Spec.DestinationAddresses != nil {
			destinationAddresses = erule.Spec.DestinationAddresses
		}
		if erule.Spec.TargetFqdns != nil {
			targetFqdns = erule.Spec.TargetFqdns
		}
		if erule.Spec.TargetUrls != nil {
			targetUrls = erule.Spec.TargetUrls
		}
		if len(targetUrls) != 0 {
			terminateTLS = true
		}
		rule := &n.ApplicationRule{
			SourceIPGroups:       &(sourceAddresses),
			DestinationAddresses: &(destinationAddresses),
			TargetFqdns:          &(targetFqdns),
			TargetUrls:           &(targetUrls),
			TerminateTLS:         &(terminateTLS),
			Protocols:            GetApplicationProtocols(erule.Spec.Protocol),
			RuleType:             GetRuleType(erule.Spec.RuleType),
			Name:                 to.StringPtr(erule.Name),
		}
		return rule
	} else if erule.Spec.RuleType == "Network" {
		destinationAddresses := []string{}
		destinationFqdns := []string{}
		if erule.Spec.DestinationAddresses != nil {
			destinationAddresses = erule.Spec.DestinationAddresses
		}
		if erule.Spec.DestinationFqdns != nil {
			destinationFqdns = erule.Spec.DestinationFqdns
		}
		rule := &n.Rule{
			SourceIPGroups:       &(sourceAddresses),
			DestinationAddresses: &(destinationAddresses),
			DestinationFqdns:     &(destinationFqdns),
			DestinationPorts:     &(erule.Spec.DestinationPorts),
			RuleType:             GetRuleType(erule.Spec.RuleType),
			IPProtocols:          GetIpProtocols(erule.Spec.Protocol),
			Name:                 to.StringPtr(erule.Name),
		}
		return rule
	}
	return rule

}

func GetApplicationProtocols(protocol []string) *[]n.FirewallPolicyRuleApplicationProtocol {
	var protocols []n.FirewallPolicyRuleApplicationProtocol

	for i := 0; i < len(protocol); i++ {
		p := strings.Split(protocol[i], ":")
		port, _ := strconv.ParseInt(p[1], 10, 64)
		protocolport := int32(port)
		var protocolType n.FirewallPolicyRuleApplicationProtocolType
		if p[0] == "HTTP" {
			protocolType = n.FirewallPolicyRuleApplicationProtocolTypeHTTP
		} else {
			protocolType = n.FirewallPolicyRuleApplicationProtocolTypeHTTPS
		}
		ruleApplicationProtocol := n.FirewallPolicyRuleApplicationProtocol{
			ProtocolType: protocolType,
			Port:         &protocolport,
		}
		protocols = append(protocols, ruleApplicationProtocol)
	}
	return &protocols
}

func GetIpProtocols(protocol []string) *[]n.FirewallPolicyRuleNetworkProtocol {
	var protocols []n.FirewallPolicyRuleNetworkProtocol

	for i := 0; i < len(protocol); i++ {
		if protocol[i] == "TCP" {
			protocols = append(protocols, n.FirewallPolicyRuleNetworkProtocolTCP)
		} else if protocol[i] == "UDP" {
			protocols = append(protocols, n.FirewallPolicyRuleNetworkProtocolUDP)
		} else if protocol[i] == "ICMP" {
			protocols = append(protocols, n.FirewallPolicyRuleNetworkProtocolICMP)
		} else {
			protocols = append(protocols, n.FirewallPolicyRuleNetworkProtocolAny)
		}
	}
	return &protocols
}

func GetRuleType(ruleType string) n.RuleType {
	var ruletype n.RuleType
	if ruleType == "Network" {
		ruletype = "NetworkRule"
	} else if ruleType == "Application" {
		ruletype = "ApplicationRule"
	}
	return ruletype
}

func GetRuleCollectionType(ruleType string) n.RuleCollectionType {
	var ruleCollectionType n.RuleCollectionType
	if ruleType == "Network" || ruleType == "Application" {
		ruleCollectionType = "FirewallPolicyFilterRuleCollection"
	} else {
		ruleCollectionType = "FirewallPolicyNatRuleCollection"
	}
	return ruleCollectionType
}

func BuildAction(action n.FirewallPolicyFilterRuleCollectionActionType) *n.FirewallPolicyFilterRuleCollectionAction {
	ruleAction := n.FirewallPolicyFilterRuleCollectionAction{
		Type: action,
	}
	return &ruleAction
}
