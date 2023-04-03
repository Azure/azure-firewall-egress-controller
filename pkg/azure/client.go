// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package controllers

import (
	"context"
	"reflect"
	"strconv"
	"strings"

	egressv1 "github.com/Azure/azure-firewall-egress-controller/pkg/api/v1"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	a "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	n "github.com/Azure/azure-sdk-for-go/services/network/mgmt/2021-03-01/network"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/to"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
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
	ipGroupClient                     *a.IPGroupsClient
	clientID                          string

	subscriptionID                  string
	resourceGroupName               string
	fwPolicyName                    string
	fwPolicyRuleCollectionGroupName string
	queue                           *Queue
	client                          client.Client
	LastNodeLabels                  map[string]map[string]string
	LastPodLabels                   map[string]map[string]string
	LastEgressRules                 egressv1.EgressrulesList

	ctx context.Context
}

// NewAzClient returns an Azure Client
func NewAzClient(subscriptionID string, resourceGroupName string, fwPolicyName string, fwPolicyRuleCollectionGroupName string, clientID string, client client.Client) AzClient {
	settings, err := auth.GetSettingsFromEnvironment()
	if err != nil {
		return nil
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		klog.Error("failed to obtain a credential: %v", err)
		return nil
	}
	ipGroupClient, err := a.NewIPGroupsClient(string(subscriptionID), cred, nil)
	if err != nil {
		klog.Error("failed to create IP group client: %v", err)
	}
	az := &azClient{
		fwPolicyClient:                    n.NewFirewallPoliciesClientWithBaseURI(settings.Environment.ResourceManagerEndpoint, string(subscriptionID)),
		fwPolicyRuleCollectionGroupClient: n.NewFirewallPolicyRuleCollectionGroupsClientWithBaseURI(settings.Environment.ResourceManagerEndpoint, string(subscriptionID)),
		ipGroupClient:                     ipGroupClient,
		clientID:                          clientID,

		subscriptionID:                  subscriptionID,
		resourceGroupName:               resourceGroupName,
		fwPolicyName:                    fwPolicyName,
		fwPolicyRuleCollectionGroupName: fwPolicyRuleCollectionGroupName,
		queue:                           NewQueue("policyBuilder"),
		client:                          client,
		LastNodeLabels:                  make(map[string]map[string]string),
		LastPodLabels:                   make(map[string]map[string]string),
		LastEgressRules:                 egressv1.EgressrulesList{},

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
	var pollers = make(map[string]*runtime.Poller[a.IPGroupsClientCreateOrUpdateResponse])
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

	//check if change in egress rule caused the reconcile request
	if az.checkIfEgressRuleChanged(req, *erulesList) {
		for _, erule := range erulesList.Items {
			var sourceIpGroups []string
			if erule.Spec.PodSelector != nil {
				for _, m := range erule.Spec.PodSelector {
					for k, v := range m {
						sourceAddress := getSourceAddressesByPodLabels(k, v, *podList)
						IPGroupName := "IPGroup-pod-" + k + v
						var addressesInIpGroup []*string
						res, err1 := az.ipGroupClient.Get(az.ctx, az.resourceGroupName, IPGroupName, &a.IPGroupsClientGetOptions{Expand: nil})
						if err1 == nil {
							addressesInIpGroup = res.IPGroup.Properties.IPAddresses
							if *res.Properties.ProvisioningState == a.ProvisioningStateUpdating && pollers[IPGroupName] != nil {
								_, err = pollers[IPGroupName].PollUntilDone(ctx, nil)
							}
						}
						if len(sourceAddress) != len(addressesInIpGroup) || checkIfElementsPresentInArray(sourceAddress, addressesInIpGroup) {
							poller := az.updateIpGroup(sourceAddress, IPGroupName)
							pollers[IPGroupName] = poller
						}
						res, err1 = az.ipGroupClient.Get(az.ctx, az.resourceGroupName, IPGroupName, &a.IPGroupsClientGetOptions{Expand: nil})
						if err1 != nil {
							klog.Error("failed to get the IP Group", err)
						}
						sourceIpGroups = append(sourceIpGroups, *res.IPGroup.ID)
					}
				}
			} else if erule.Spec.NodeSelector != nil {
				for _, m := range erule.Spec.NodeSelector {
					for k, v := range m {
						sourceAddress := getSourceAddressesByNodeLabels(k, v, *nodeList)
						IPGroupName := "IPGroup-node-" + k + v
						var addressesInIpGroup []*string
						res, err1 := az.ipGroupClient.Get(az.ctx, az.resourceGroupName, IPGroupName, &a.IPGroupsClientGetOptions{Expand: nil})
						if err1 == nil {
							addressesInIpGroup = res.IPGroup.Properties.IPAddresses
							if *res.Properties.ProvisioningState == a.ProvisioningStateUpdating && pollers[IPGroupName] != nil {
								_, err = pollers[IPGroupName].PollUntilDone(ctx, nil)
							}
						}
						if err1 != nil || len(sourceAddress) != len(addressesInIpGroup) || checkIfElementsPresentInArray(sourceAddress, addressesInIpGroup) {
							poller := az.updateIpGroup(sourceAddress, IPGroupName)
							pollers[IPGroupName] = poller
						}
						res, err1 = az.ipGroupClient.Get(az.ctx, az.resourceGroupName, IPGroupName, &a.IPGroupsClientGetOptions{Expand: nil})
						if err1 != nil {
							klog.Error("failed to get the IP Group", err)
						}
						sourceIpGroups = append(sourceIpGroups, *res.IPGroup.ID)
					}
				}
			}
			erulesSourceAddresses[erule.Name] = sourceIpGroups
		}
		for _, poller := range pollers {
			_, err = poller.PollUntilDone(ctx, nil)
			if err != nil {
				klog.Error("failed to pull the result: %v", err)
			}
		}
		klog.Info("Ip Group update complete........")
		klog.Info("Source Addresses:", erulesSourceAddresses)

		az.BuildPolicy(*erulesList, erulesSourceAddresses)

	} else if checkIfNodeChanged(req, *nodeList) || checkIfPodChanged(req, *podList) {
		var sourceAddress []*string
		ruleExistsOnLabels := az.checkIfRuleExistsOnNodeOrPod(ctx, req, *erulesList, *nodeList, *podList)
		for label, address := range ruleExistsOnLabels {
			res, err1 := az.ipGroupClient.Get(az.ctx, az.resourceGroupName, label, &a.IPGroupsClientGetOptions{Expand: nil})
			if err1 == nil {
				sourceAddress = res.IPGroup.Properties.IPAddresses
			}
			if len(address) != len(sourceAddress) || checkIfElementsPresentInArray(address, sourceAddress) {
				poller := az.updateIpGroup(address, label)
				_, err = poller.PollUntilDone(ctx, nil)
				if err != nil {
					klog.Error("failed to pull the result: %v", err)
				}
				klog.Info("Ip Group update complete........\n\n")
			}
		}
	}
	return
}

func (az *azClient) checkIfEgressRuleChanged(req ctrl.Request, erulesList egressv1.EgressrulesList) bool {
	//check if erule is in current egress rules
	for _, erule := range erulesList.Items {
		if erule.Name == req.NamespacedName.Name {
			az.LastEgressRules = erulesList
			return true
		}
	}
	//check if erule is in last egress rules, it means the erule is deleted.
	for _, erule := range az.LastEgressRules.Items {
		if erule.Name == req.NamespacedName.Name {
			az.LastEgressRules = erulesList
			return true
		}
	}
	return false
}

func checkIfNodeChanged(req ctrl.Request, nodeList corev1.NodeList) bool {
	for _, node := range nodeList.Items {
		if node.Name == req.NamespacedName.Name {
			return true
		}
	}
	return false
}

func checkIfPodChanged(req ctrl.Request, podList corev1.PodList) bool {
	for _, pod := range podList.Items {
		if pod.Name == req.NamespacedName.Name {
			return true
		}
	}
	return false
}

func (az *azClient) checkIfRuleExistsOnNodeOrPod(ctx context.Context, req ctrl.Request, erulesList egressv1.EgressrulesList, nodeList corev1.NodeList, podList corev1.PodList) map[string][]*string {
	if checkIfNodeChanged(req, nodeList) {
		var rulesExistsOnNodeLabels = make(map[string][]*string)
		node := &corev1.Node{}
		if err := az.client.Get(ctx, req.NamespacedName, node); err != nil {
			klog.Error(err, "unable to fetch Node")
		}
		for _, erule := range erulesList.Items {
			if erule.Spec.NodeSelector != nil {
				for _, m := range erule.Spec.NodeSelector {
					for k, v := range m {
						if checkIfLabelExists(k, v, node.ObjectMeta.Labels) {
							sourceAddress := getSourceAddressesByNodeLabels(k, v, nodeList)
							rulesExistsOnNodeLabels["IPGroup-node-"+k+v] = sourceAddress
						}
					}
				}
			}
		}
		if !reflect.DeepEqual(node.ObjectMeta.Labels, az.LastNodeLabels[node.Name]) {
			// Node selector has been modified, get the changes
			oldSelector := az.LastNodeLabels[node.Name]
			newSelector := node.ObjectMeta.Labels
			changes := make(map[string]string)
			for key, value := range oldSelector {
				if newSelector[key] != value {
					changes[key] = value
				}
			}

			for _, erule := range erulesList.Items {
				if erule.Spec.NodeSelector != nil {
					for _, m := range erule.Spec.NodeSelector {
						for k, v := range m {
							if checkIfLabelExists(k, v, changes) {
								sourceAddress := getSourceAddressesByNodeLabels(k, v, nodeList)
								rulesExistsOnNodeLabels["IPGroup-node-"+k+v] = sourceAddress
							}
						}
					}
				}

			}
		}
		az.LastNodeLabels[node.Name] = node.ObjectMeta.Labels
		return rulesExistsOnNodeLabels
	} else {
		var rulesExistsOnPodLabels = make(map[string][]*string)
		pod := &corev1.Pod{}
		if err := az.client.Get(ctx, req.NamespacedName, pod); err != nil {
			klog.Error(err, "unable to fetch Pod")
		}
		for _, erule := range erulesList.Items {
			if erule.Spec.PodSelector != nil {
				for _, m := range erule.Spec.PodSelector {
					for k, v := range m {
						if checkIfLabelExists(k, v, pod.ObjectMeta.Labels) {
							sourceAddress := getSourceAddressesByPodLabels(k, v, podList)
							rulesExistsOnPodLabels["IPGroup-pod-"+k+v] = sourceAddress
						}
					}
				}
			}
		}
		if !reflect.DeepEqual(pod.ObjectMeta.Labels, az.LastPodLabels[pod.Name]) {
			// Pod selector has been modified, get the changes
			oldSelector := az.LastPodLabels[pod.Name]
			newSelector := pod.ObjectMeta.Labels
			changes := make(map[string]string)
			for key, value := range oldSelector {
				if newSelector[key] != value {
					changes[key] = value
				}
			}

			for _, erule := range erulesList.Items {
				if erule.Spec.PodSelector != nil {
					for _, m := range erule.Spec.PodSelector {
						for k, v := range m {
							if checkIfLabelExists(k, v, changes) {
								sourceAddress := getSourceAddressesByPodLabels(k, v, podList)
								rulesExistsOnPodLabels["IPGroup-pod-"+k+v] = sourceAddress
							}
						}
					}
				}
			}
		}
		az.LastNodeLabels[pod.Name] = pod.ObjectMeta.Labels
		return rulesExistsOnPodLabels
	}
}

func (az *azClient) updateIpGroup(sourceAddress []*string, ipGroupsName string) *runtime.Poller[a.IPGroupsClientCreateOrUpdateResponse] {
	poller, err := az.ipGroupClient.BeginCreateOrUpdate(az.ctx, az.resourceGroupName, ipGroupsName, a.IPGroup{
		Location: to.StringPtr("eastus"),
		Tags:     map[string]*string{},
		Properties: &a.IPGroupPropertiesFormat{
			IPAddresses: sourceAddress,
		},
	}, nil)
	if err != nil {
		klog.Error("Error updating the Ip Group: ", err)
	}
	klog.Info("Updating Ip Group: ", ipGroupsName)

	return poller
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
	if err1 != nil {
		klog.Error("Error updating the Firewall Policy: ", err1, "\n\n")
		return
	}

	klog.Info("Firewall Policy update successful.....\n\n")
	return
}

func (az *azClient) buildFirewallConfig(erulesList egressv1.EgressrulesList, erulesSourceAddresses map[string][]string) *[]n.BasicFirewallPolicyRuleCollection {
	var ruleCollections []n.BasicFirewallPolicyRuleCollection

	for _, erule := range erulesList.Items {
		if len(erulesSourceAddresses[erule.Name]) != 0 {
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
			SourceIPGroups:       &(sourceAddresses),
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
			SourceIPGroups:       &(sourceAddresses),
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
