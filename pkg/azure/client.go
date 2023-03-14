// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package controllers

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	egressv1 "github.com/Azure/azure-firewall-egress-controller/pkg/api/v1"
	n "github.com/Azure/azure-sdk-for-go/services/network/mgmt/2021-03-01/network"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/to"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AzClient is an interface for client to Azure
type AzClient interface {
	SetAuthorizer(authorizer autorest.Authorizer)
	UpdateFirewallPolicy(ctx context.Context, req ctrl.Request) error
	getEgressRules(ctx context.Context, req ctrl.Request) error
	BuildPolicy(erule egressv1.EgressrulesList, erulesSourceAddresses map[string][]string) error
}

type azClient struct {
	fwPolicyClient                    n.FirewallPoliciesClient
	fwPolicyRuleCollectionGroupClient n.FirewallPolicyRuleCollectionGroupsClient
	clientID                          string

	subscriptionID                  string
	resourceGroupName               string
	fwPolicyName                    string
	fwPolicyRuleCollectionGroupName string
	queue                           *Queue
	client                          client.Client

	ctx context.Context
}

// NewAzClient returns an Azure Client
func NewAzClient(subscriptionID string, resourceGroupName string, fwPolicyName string, fwPolicyRuleCollectionGroupName string, clientID string, client client.Client) AzClient {
	settings, err := auth.GetSettingsFromEnvironment()
	if err != nil {
		return nil
	}

	az := &azClient{
		fwPolicyClient:                    n.NewFirewallPoliciesClientWithBaseURI(settings.Environment.ResourceManagerEndpoint, string(subscriptionID)),
		fwPolicyRuleCollectionGroupClient: n.NewFirewallPolicyRuleCollectionGroupsClientWithBaseURI(settings.Environment.ResourceManagerEndpoint, string(subscriptionID)),
		clientID:                          clientID,

		subscriptionID:                  subscriptionID,
		resourceGroupName:               resourceGroupName,
		fwPolicyName:                    fwPolicyName,
		fwPolicyRuleCollectionGroupName: fwPolicyRuleCollectionGroupName,
		queue:                           NewQueue("policyBuilder"),
		client:                          client,

		ctx: context.Background(),
	}

	worker := NewWorker(az.queue)
	go worker.DoWork()

	return az
}

func (az *azClient) SetAuthorizer(authorizer autorest.Authorizer) {
	az.fwPolicyClient.Authorizer = authorizer
	az.fwPolicyRuleCollectionGroupClient.Authorizer = authorizer
}

func (az *azClient) UpdateFirewallPolicy(ctx context.Context, req ctrl.Request) (err error) {
	az.checkIfPolicyExists()

	az.queue.AddJob(Job{
		Request:  req,
		ctx:      ctx,
		AzClient: az,
	})
	return
}

func (az *azClient) getEgressRules(ctx context.Context, req ctrl.Request) (err error) {
	var erulesSourceAddresses = make(map[string][]string)
	erulesList := &egressv1.EgressrulesList{}
	listOpts := []client.ListOption{
		client.InNamespace("default"),
	}
	if err := az.client.List(ctx, erulesList, listOpts...); err != nil {
		return err
	}

	podList := &corev1.PodList{}
	if err := az.client.List(ctx, podList, listOpts...); err != nil {
		return err
	}

	nodeList := &corev1.NodeList{}
	if err := az.client.List(ctx, nodeList, []client.ListOption{}...); err != nil {
		return err
	}

	for _, erule := range erulesList.Items {
		var sourceAddress []string
		if erule.Spec.PodSelector != nil {
			for _, pod := range podList.Items {
				if pod.ObjectMeta.Namespace != "kube-system" {
					if pod.Status.Phase == "Running" && checkIfLabelExists(erule.Spec.PodSelector, pod.ObjectMeta.Labels) {
						sourceAddress = append(sourceAddress, pod.Status.HostIP)
					}
				}
			}
		}

		if erule.Spec.NodeSelector != nil {
			for _, node := range nodeList.Items {
				if checkIfLabelExists(erule.Spec.NodeSelector, node.ObjectMeta.Labels) {
					sourceAddress = append(sourceAddress, node.Status.Addresses[0].Address)
				}
			}
		}

		sourceAddress = unique(sourceAddress)
		erulesSourceAddresses[erule.Name] = sourceAddress
	}

	fmt.Printf("Erules source addresses %#v\n\n", erulesSourceAddresses)

	az.BuildPolicy(*erulesList, erulesSourceAddresses)
	return
}

func (az *azClient) BuildPolicy(erulesList egressv1.EgressrulesList, erulesSourceAddresses map[string][]string) (err error) {
	ruleCollections := az.buildFirewallConfig(erulesList, erulesSourceAddresses)

	fwRuleCollectionGrpObj := &n.FirewallPolicyRuleCollectionGroup{
		FirewallPolicyRuleCollectionGroupProperties: &(n.FirewallPolicyRuleCollectionGroupProperties{
			Priority:        to.Int32Ptr(400),
			RuleCollections: ruleCollections,
		}),
	}

	fwRUleCollectionGrp, err1 := az.fwPolicyRuleCollectionGroupClient.CreateOrUpdate(az.ctx, string(az.resourceGroupName), az.fwPolicyName, az.fwPolicyRuleCollectionGroupName, *fwRuleCollectionGrpObj)

	err1 = fwRUleCollectionGrp.WaitForCompletionRef(az.ctx, az.fwPolicyRuleCollectionGroupClient.BaseClient.Client)
	fmt.Printf("Error in updating the policy.......... : %#v\n\n", err1)
	if err1 != nil {
		return
	}
	fmt.Printf("Firewall policy updated.....\n")
	fmt.Printf("------------------------------------\n")
	fmt.Printf("\n")
	return
}

func (az *azClient) buildFirewallConfig(erulesList egressv1.EgressrulesList, erulesSourceAddresses map[string][]string) *[]n.BasicFirewallPolicyRuleCollection {
	var ruleCollections []n.BasicFirewallPolicyRuleCollection

	for _, erule := range erulesList.Items {
		if (len(erulesSourceAddresses[erule.Name]) != 0) && (erulesSourceAddresses[erule.Name] != nil) {
			if len(ruleCollections) == 0 || az.notFoundRuleCollection(erule, ruleCollections) {
				ruleCollection := az.createRuleCollection(erule, erulesSourceAddresses)
				ruleCollections = append(ruleCollections, ruleCollection)
			} else {
				for i := 0; i < len(ruleCollections); i++ {
					ruleCollection := ruleCollections[i].(*n.FirewallPolicyFilterRuleCollection)
					if erule.Spec.RuleCollectionName == *ruleCollection.Name {
						rules := *ruleCollection.Rules
						rule := az.getRule(erule, erulesSourceAddresses)
						rules = append(rules, rule)
						ruleCollection.Rules = &rules
					}
				}
			}
		}

	}
	return &ruleCollections
}

func (az *azClient) notFoundRuleCollection(erule egressv1.Egressrules, ruleCollections []n.BasicFirewallPolicyRuleCollection) bool {
	for i := 0; i < len(ruleCollections); i++ {
		ruleCollection := ruleCollections[i].(*n.FirewallPolicyFilterRuleCollection)
		if erule.Spec.RuleCollectionName == *ruleCollection.Name {
			return false
		}
	}
	return true
}

func (az *azClient) createRuleCollection(erule egressv1.Egressrules, erulesSourceAddresses map[string][]string) n.BasicFirewallPolicyRuleCollection {
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
		Action:             az.buildAction(erule.Spec.Action),
		Priority:           &priority,
		RuleCollectionType: az.getRuleCollectionType(erule.Spec.RuleType),
		Rules:              az.buildRules(erule, erulesSourceAddresses),
	}
	return ruleCollection
}

func (az *azClient) buildRules(erule egressv1.Egressrules, erulesSourceAddresses map[string][]string) *[]n.BasicFirewallPolicyRule {
	var rules []n.BasicFirewallPolicyRule
	rule := az.getRule(erule, erulesSourceAddresses)
	rules = append(rules, rule)
	return &rules
}

func (az *azClient) getRule(erule egressv1.Egressrules, erulesSourceAddresses map[string][]string) n.BasicFirewallPolicyRule {

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
			SourceAddresses:      &(sourceAddresses),
			DestinationAddresses: &(destinationAddresses),
			TargetFqdns:          &(targetFqdns),
			TargetUrls:           &(targetUrls),
			TerminateTLS:         &(terminateTLS),
			Protocols:            az.getApplicationProtocols(erule.Spec.Protocol),
			RuleType:             az.getRuleType(erule.Spec.RuleType),
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
			SourceAddresses:      &(sourceAddresses),
			DestinationAddresses: &(destinationAddresses),
			DestinationFqdns:     &(destinationFqdns),
			DestinationPorts:     &(erule.Spec.DestinationPorts),
			RuleType:             az.getRuleType(erule.Spec.RuleType),
			IPProtocols:          az.getIpProtocols(erule.Spec.Protocol),
			Name:                 to.StringPtr(erule.Name),
		}
		return rule
	}
	return rule

}

func (az *azClient) getApplicationProtocols(protocol []string) *[]n.FirewallPolicyRuleApplicationProtocol {
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

func (az *azClient) getIpProtocols(protocol []string) *[]n.FirewallPolicyRuleNetworkProtocol {
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

func (az *azClient) getRuleType(ruleType string) n.RuleType {
	var ruletype n.RuleType
	if ruleType == "Network" {
		ruletype = "NetworkRule"
	} else if ruleType == "Application" {
		ruletype = "ApplicationRule"
	}
	return ruletype
}

func (az *azClient) getRuleCollectionType(ruleType string) n.RuleCollectionType {
	var ruleCollectionType n.RuleCollectionType
	if ruleType == "Network" || ruleType == "Application" {
		ruleCollectionType = "FirewallPolicyFilterRuleCollection"
	} else {
		ruleCollectionType = "FirewallPolicyNatRuleCollection"
	}
	return ruleCollectionType
}

func (az *azClient) buildAction(action n.FirewallPolicyFilterRuleCollectionActionType) *n.FirewallPolicyFilterRuleCollectionAction {
	ruleAction := n.FirewallPolicyFilterRuleCollectionAction{
		Type: action,
	}
	return &ruleAction
}

func (az *azClient) checkIfPolicyExists() (err error) {
	fwObj := &n.FirewallPolicy{
		Location: to.StringPtr("westus2"),
	}

	_, err = az.fwPolicyClient.Get(az.ctx, string(az.resourceGroupName), az.fwPolicyName, "True")
	if err != nil {
		newfwPolicy, err1 := az.fwPolicyClient.CreateOrUpdate(az.ctx, string(az.resourceGroupName), az.fwPolicyName, *fwObj)
		if err1 != nil {
			return
		}
		err = newfwPolicy.WaitForCompletionRef(az.ctx, az.fwPolicyClient.BaseClient.Client)
	}
	return
}
