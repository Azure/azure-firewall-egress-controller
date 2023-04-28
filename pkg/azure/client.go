// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package azure

import (
	"context"
	"reflect"

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

const (
	IpGroupNamePrefix string = "IPGroup-node-"
)

var pollers = make(map[string]*runtime.Poller[a.IPGroupsClientCreateOrUpdateResponse])
var firewallPolicyLoc = ""

// AzClient is an interface for client to Azure
type AzClient interface {
	SetAuthorizer(authorizer autorest.Authorizer)
	UpdateFirewallPolicy(ctx context.Context, req ctrl.Request) error
	processRequest(ctx context.Context, req ctrl.Request) error
	BuildPolicy(erule egressv1.EgressrulesList, erulesSourceAddresses map[string][]string) error
	AddTaints(ctx context.Context, req ctrl.Request)
	RemoveTaints(ctx context.Context, req ctrl.Request)
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
	lastNodeLabels                  map[string]map[string]string
	lastEgressRules                 egressv1.EgressrulesList

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
		lastNodeLabels:                  make(map[string]map[string]string),
		lastEgressRules:                 egressv1.EgressrulesList{},

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
	az.queue.AddJob(Job{
		Request:  req,
		ctx:      ctx,
		AzClient: az,
	})

	if firewallPolicyLoc == "" {
		az.fetchFirewallPolicyLocation()
	}

	return
}

func (az *azClient) processRequest(ctx context.Context, req ctrl.Request) (err error) {
	var erulesSourceAddresses = make(map[string][]string)
	erulesList := &egressv1.EgressrulesList{}
	listOpts := []client.ListOption{}
	if err := az.client.List(ctx, erulesList, listOpts...); err != nil {
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
			if erule.Spec.NodeSelector != nil {
				for _, m := range erule.Spec.NodeSelector {
					for k, v := range m {
						sourceAddress := getSourceAddressesByNodeLabels(k, v, *nodeList)
						IPGroupName := IpGroupNamePrefix + k + v
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
							klog.Error("failed to get the IP Group", err1)
						}
						sourceIpGroups = append(sourceIpGroups, *res.IPGroup.ID)
					}
				}
			}
			erulesSourceAddresses[erule.Name] = sourceIpGroups
		}
		klog.Info("Source Addresses:", erulesSourceAddresses)

		az.BuildPolicy(*erulesList, erulesSourceAddresses)

	} else if checkIfNodeChanged(req, *nodeList) {
		var node_pollers = make(map[string]*runtime.Poller[a.IPGroupsClientCreateOrUpdateResponse])
		ruleExistsOnLabels := az.checkIfRuleExistsOnNode(ctx, req, *erulesList, *nodeList)
		for IPGroupName, address := range ruleExistsOnLabels {
			var addressesInIpGroup []*string
			res, err1 := az.ipGroupClient.Get(az.ctx, az.resourceGroupName, IPGroupName, &a.IPGroupsClientGetOptions{Expand: nil})
			if err1 == nil {
				addressesInIpGroup = res.IPGroup.Properties.IPAddresses
				if *res.Properties.ProvisioningState == a.ProvisioningStateUpdating && pollers[IPGroupName] != nil {
					_, err = pollers[IPGroupName].PollUntilDone(ctx, nil)
				}
			}
			if len(address) != len(addressesInIpGroup) || checkIfElementsPresentInArray(address, addressesInIpGroup) {
				poller := az.updateIpGroup(address, IPGroupName)
				pollers[IPGroupName] = poller
				node_pollers[IPGroupName] = poller
			}
		}
		go az.WaitForNodeIpGroupUpdate(ctx, req, node_pollers)
	}
	return
}

func (az *azClient) checkIfEgressRuleChanged(req ctrl.Request, erulesList egressv1.EgressrulesList) bool {
	//check if erule is in current egress rules
	for _, erule := range erulesList.Items {
		if erule.Name == req.NamespacedName.Name {
			az.lastEgressRules = erulesList
			return true
		}
	}
	//check if erule is in last egress rules, it means the erule is deleted.
	for _, erule := range az.lastEgressRules.Items {
		if erule.Name == req.NamespacedName.Name {
			az.lastEgressRules = erulesList
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

func (az *azClient) checkIfRuleExistsOnNode(ctx context.Context, req ctrl.Request, erulesList egressv1.EgressrulesList, nodeList corev1.NodeList) map[string][]*string {
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
						IPGroupName := IpGroupNamePrefix + k + v
						sourceAddress := getSourceAddressesByNodeLabels(k, v, nodeList)
						rulesExistsOnNodeLabels[IPGroupName] = sourceAddress
					}
				}
			}
		}
	}
	if !reflect.DeepEqual(node.ObjectMeta.Labels, az.lastNodeLabels[node.Name]) {
		// Node selector has been modified, get the changes
		oldSelector := az.lastNodeLabels[node.Name]
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
							IPGroupName := IpGroupNamePrefix + k + v
							sourceAddress := getSourceAddressesByNodeLabels(k, v, nodeList)
							rulesExistsOnNodeLabels[IPGroupName] = sourceAddress
						}
					}
				}
			}

		}
	}
	az.lastNodeLabels[node.Name] = node.ObjectMeta.Labels
	return rulesExistsOnNodeLabels
}

func (az *azClient) updateIpGroup(sourceAddress []*string, ipGroupsName string) *runtime.Poller[a.IPGroupsClientCreateOrUpdateResponse] {
	poller, err := az.ipGroupClient.BeginCreateOrUpdate(az.ctx, az.resourceGroupName, ipGroupsName, a.IPGroup{
		Location: to.StringPtr(firewallPolicyLoc),
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
	ruleCollections := BuildFirewallConfig(erulesList, erulesSourceAddresses)

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

func (az *azClient) fetchFirewallPolicyLocation() (err error) {
	fwPolicyObj, err := az.fwPolicyClient.Get(az.ctx, string(az.resourceGroupName), az.fwPolicyName, "True")

	if err != nil {
		klog.Error("Firewall Policy not found")
	} else {
		firewallPolicyLoc = *fwPolicyObj.Location
	}
	return
}
