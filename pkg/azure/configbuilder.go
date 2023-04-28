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
			for _, rule := range erule.Spec.Rules {
				if len(ruleCollections) == 0 || NotFoundRuleCollection(rule, ruleCollections) {
					ruleCollection := BuildRuleCollection(erule, rule, erulesSourceAddresses)
					ruleCollections = append(ruleCollections, ruleCollection)
				} else {
					for i := 0; i < len(ruleCollections); i++ {
						ruleCollection := ruleCollections[i].(*n.FirewallPolicyFilterRuleCollection)
						if rule.RuleCollectionName == *ruleCollection.Name {
							fwRules := *ruleCollection.Rules
							fwRule := GetRule(erule, rule, erulesSourceAddresses)
							fwRules = append(fwRules, fwRule)
							ruleCollection.Rules = &fwRules
						}
					}
				}
			}
		}

	}
	return &ruleCollections
}

func NotFoundRuleCollection(rule egressv1.EgressrulesRulesSpec, ruleCollections []n.BasicFirewallPolicyRuleCollection) bool {
	for i := 0; i < len(ruleCollections); i++ {
		ruleCollection := ruleCollections[i].(*n.FirewallPolicyFilterRuleCollection)
		if rule.RuleCollectionName == *ruleCollection.Name {
			return false
		}
	}
	return true
}

func BuildRuleCollection(erule egressv1.Egressrules, rule egressv1.EgressrulesRulesSpec, erulesSourceAddresses map[string][]string) n.BasicFirewallPolicyRuleCollection {
	var priority int32
	if rule.Action == "Allow" {
		if rule.RuleType == "Application" {
			priority = 210
		} else {
			priority = 110
		}
	} else {
		if rule.RuleType == "Application" {
			priority = 200
		} else {
			priority = 100
		}
	}

	ruleCollection := &n.FirewallPolicyFilterRuleCollection{
		Name:               to.StringPtr(rule.RuleCollectionName),
		Action:             BuildAction(rule.Action),
		Priority:           &priority,
		RuleCollectionType: GetRuleCollectionType(rule.RuleType),
		Rules:              BuildRules(erule, rule, erulesSourceAddresses),
	}
	return ruleCollection
}

func BuildRules(erule egressv1.Egressrules, rule egressv1.EgressrulesRulesSpec, erulesSourceAddresses map[string][]string) *[]n.BasicFirewallPolicyRule {
	var fwRules []n.BasicFirewallPolicyRule
	fwRule := GetRule(erule, rule, erulesSourceAddresses)
	fwRules = append(fwRules, fwRule)
	return &fwRules
}

func GetRule(erule egressv1.Egressrules, rule egressv1.EgressrulesRulesSpec, erulesSourceAddresses map[string][]string) n.BasicFirewallPolicyRule {

	sourceAddresses := erulesSourceAddresses[erule.Name]
	var fwRule n.BasicFirewallPolicyRule

	if rule.RuleType == "Application" {
		targetFqdns := []string{}
		targetUrls := []string{}
		var terminateTLS = false
		destinationAddresses := []string{}

		if rule.DestinationAddresses != nil {
			destinationAddresses = rule.DestinationAddresses
		}
		if rule.TargetFqdns != nil {
			targetFqdns = rule.TargetFqdns
		}
		if rule.TargetUrls != nil {
			targetUrls = rule.TargetUrls
		}
		if len(targetUrls) != 0 {
			terminateTLS = true
		}
		fwRule := &n.ApplicationRule{
			SourceIPGroups:       &(sourceAddresses),
			DestinationAddresses: &(destinationAddresses),
			TargetFqdns:          &(targetFqdns),
			TargetUrls:           &(targetUrls),
			TerminateTLS:         &(terminateTLS),
			Protocols:            GetApplicationProtocols(rule.Protocol),
			RuleType:             GetRuleType(rule.RuleType),
			Name:                 to.StringPtr(rule.RuleName),
		}
		return fwRule
	} else if rule.RuleType == "Network" {
		destinationAddresses := []string{}
		destinationFqdns := []string{}
		if rule.DestinationAddresses != nil {
			destinationAddresses = rule.DestinationAddresses
		}
		if rule.DestinationFqdns != nil {
			destinationFqdns = rule.DestinationFqdns
		}
		fwRule := &n.Rule{
			SourceIPGroups:       &(sourceAddresses),
			DestinationAddresses: &(destinationAddresses),
			DestinationFqdns:     &(destinationFqdns),
			DestinationPorts:     &(rule.DestinationPorts),
			RuleType:             GetRuleType(rule.RuleType),
			IPProtocols:          GetIpProtocols(rule.Protocol),
			Name:                 to.StringPtr(rule.RuleName),
		}
		return fwRule
	}
	return fwRule

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
