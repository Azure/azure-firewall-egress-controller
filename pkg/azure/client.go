// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package azure

import (
	"context"
	"reflect"
	"time"

	egressv1 "github.com/Azure/azure-firewall-egress-controller/pkg/api/v1"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	a "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v2"
	n "github.com/Azure/azure-sdk-for-go/services/network/mgmt/2021-03-01/network"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/orcaman/concurrent-map/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	IpGroupNamePrefix string = "IPGroup-node-"
)

var pollers = make(map[string]*runtime.Poller[a.IPGroupsClientCreateOrUpdateResponse])
var lastNodeLabels = cmap.New[map[string]string]()
var firewallPolicyLoc = ""

// AzClient is an interface for client to Azure
type AzClient interface {
	SetAuthorizer(authorizer autorest.Authorizer)
	UpdateFirewallPolicy(ctx context.Context, req ctrl.Request) error
	processRequest(ctx context.Context, req ctrl.Request) error
	BuildPolicy(items egressv1.EgressrulesList, erulesSourceAddresses map[string][]string) error
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
		lastEgressRules:                 egressv1.EgressrulesList{},

		ctx: context.Background(),
	}

	if firewallPolicyLoc == "" {
		az.fetchFirewallPolicyLocation()
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
	az.checkIfJobToBeAddedToChannel(ctx, req)

	return
}

func (az *azClient) checkIfJobToBeAddedToChannel(ctx context.Context, req ctrl.Request) (err error) {
	erulesList := &egressv1.EgressrulesList{}
	if err := az.client.List(ctx, erulesList, []client.ListOption{}...); err != nil {
		return err
	}
	nodeList := &corev1.NodeList{}
	if err := az.client.List(ctx, nodeList, []client.ListOption{}...); err != nil {
		return err
	}

	if az.checkIfNodeChanged(req, *nodeList) {
		node := &corev1.Node{}
		if err := az.client.Get(ctx, req.NamespacedName, node); err != nil {
			klog.Error(err, "unable to fetch Node")
		}
		newNodeSelector := node.ObjectMeta.Labels
		oldNodeSelector, _ := lastNodeLabels.Get(node.Name)
		if checkIfRuleExistsOnNode(*node, *erulesList, newNodeSelector, oldNodeSelector) {
			az.queue.AddJob(Job{
				Request:  req,
				ctx:      ctx,
				AzClient: az,
			})
		} else {
			lastNodeLabels.Set(node.Name, node.ObjectMeta.Labels)
			az.RemoveTaints(ctx, req)

		}
	} else if az.checkIfEgressRuleChanged(req, *erulesList) {
		az.queue.AddJob(Job{
			Request:  req,
			ctx:      ctx,
			AzClient: az,
		})
	}
	return
}

func (az *azClient) processRequest(ctx context.Context, req ctrl.Request) (err error) {
	processEventStart := time.Now()

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
	if az.checkIfNodeChanged(req, *nodeList) {
		var node_pollers = make(map[string]*runtime.Poller[a.IPGroupsClientCreateOrUpdateResponse])
		ruleExistsOnLabels := az.fetchNodeIps(ctx, req, *erulesList, *nodeList)
		for IPGroupName, address := range ruleExistsOnLabels {
			var addressesInIpGroup []*string
			res, err1 := az.ipGroupClient.Get(az.ctx, az.resourceGroupName, IPGroupName, &a.IPGroupsClientGetOptions{Expand: nil})
			if err1 == nil {
				addressesInIpGroup = res.IPGroup.Properties.IPAddresses
				if *res.Properties.ProvisioningState == a.ProvisioningStateUpdating && pollers[IPGroupName] != nil {
					klog.Info("waiting for the IP group update to complete......")
					_, err = pollers[IPGroupName].PollUntilDone(ctx, nil)
				}
			}
			if len(address) != len(addressesInIpGroup) || checkIfElementsPresentInArray(address, addressesInIpGroup) {
				poller := az.updateIpGroup(address, IPGroupName)
				pollers[IPGroupName] = poller
				node_pollers[IPGroupName] = poller
			} else {
				klog.Info("IP Group has NOT changed! No need to connect to ARM.")
			}
		}
		go az.WaitForNodeIpGroupUpdate(ctx, req, node_pollers)
	} else {
		for _, item := range erulesList.Items {
			for _, egressrule := range item.Spec.EgressRules {
				var sourceIpGroups []string
				if egressrule.NodeSelector != nil {
					for _, m := range egressrule.NodeSelector {
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
				erulesSourceAddresses[egressrule.Name] = sourceIpGroups
			}
		}

		az.BuildPolicy(*erulesList, erulesSourceAddresses)
	}
	duration := time.Now().Sub(processEventStart)
	klog.Infof("Completed last event loop run in: %+v", duration)
	return
}

func (az *azClient) checkIfEgressRuleChanged(req ctrl.Request, erulesList egressv1.EgressrulesList) bool {
	//check if erule is in current egress rules
	for _, item := range erulesList.Items {
		if item.Name == req.NamespacedName.Name {
			az.lastEgressRules = erulesList
			return true
		}
	}
	//check if erule is in last egress rules, it means the erule is deleted.
	for _, item := range az.lastEgressRules.Items {
		if item.Name == req.NamespacedName.Name {
			az.lastEgressRules = erulesList
			return true
		}
	}
	return false
}

func (az *azClient) checkIfNodeChanged(req ctrl.Request, nodeList corev1.NodeList) bool {
	for _, node := range nodeList.Items {
		if node.Name == req.NamespacedName.Name {
			return true
		}
	}
	return false
}

func (az *azClient) fetchNodeIps(ctx context.Context, req ctrl.Request, erulesList egressv1.EgressrulesList, nodeList corev1.NodeList) map[string][]*string {
	var rulesExistsOnNodeLabels = make(map[string][]*string)
	node := &corev1.Node{}
	if err := az.client.Get(ctx, req.NamespacedName, node); err != nil {
		klog.Error(err, "unable to fetch Node")
	}
	for _, item := range erulesList.Items {
		for _, egressrule := range item.Spec.EgressRules {
			if egressrule.NodeSelector != nil {
				for _, m := range egressrule.NodeSelector {
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
	}
	oldNodeSelector, _ := lastNodeLabels.Get(node.Name)
	if !reflect.DeepEqual(node.ObjectMeta.Labels, oldNodeSelector) {
		// Node selector has been modified, get the changes
		newNodeSelector := node.ObjectMeta.Labels
		changes := make(map[string]string)
		for key, value := range oldNodeSelector {
			if newNodeSelector[key] != value {
				changes[key] = value
			}
		}

		for _, item := range erulesList.Items {
			for _, egressrule := range item.Spec.EgressRules {
				if egressrule.NodeSelector != nil {
					for _, m := range egressrule.NodeSelector {
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
	}
	lastNodeLabels.Set(node.Name, node.ObjectMeta.Labels)
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

	configJSON, _ := dumpSanitizedJSON(fwRuleCollectionGrpObj)
	klog.Infof("Generated config:\n%s", string(configJSON))

	klog.Info("BEGIN firewall policy deployment")

	fwRUleCollectionGrp, err1 := az.fwPolicyRuleCollectionGroupClient.CreateOrUpdate(az.ctx, string(az.resourceGroupName), az.fwPolicyName, az.fwPolicyRuleCollectionGroupName, *fwRuleCollectionGrpObj)

	err1 = fwRUleCollectionGrp.WaitForCompletionRef(az.ctx, az.fwPolicyRuleCollectionGroupClient.BaseClient.Client)
	if err1 != nil {
		klog.Error("Error updating the Firewall Policy: ", err1)
		return
	}

	klog.Info("Applied generated firewall policy configuration.....")
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
