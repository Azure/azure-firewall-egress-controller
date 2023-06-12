// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package azure

import (
	"context"
	"time"

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

// AzClient is an interface for client to Azure
type AzClient interface {
	SetAuthorizer(authorizer autorest.Authorizer)
	FetchFirewallPolicyLocation() string
	UpdateFirewallPolicy(ctx context.Context, req ctrl.Request) error
	processRequest(ctx context.Context, req ctrl.Request, nodesWithFwTaint []*corev1.Node) error
	BuildPolicy(items egressv1.EgressrulesList, erulesSourceAddresses map[string][]string) error
	AddTaints(ctx context.Context, req ctrl.Request)
	RemoveTaints(ctx context.Context, node *corev1.Node)
}

type azClient struct {
	fwPolicyClient                    *a.FirewallPoliciesClient
	fwPolicyRuleCollectionGroupClient n.FirewallPolicyRuleCollectionGroupsClient
	ipGroupClient                     *a.IPGroupsClient
	clientID                          string

	subscriptionID                      string
	resourceGroupName                   string
	fwPolicyName                        string
	fwPolicyRuleCollectionGroupName     string
	fwPolicyRuleCollectionGroupPriority int32
	firewallPolicyLoc                   string
	queue                               *Queue
	client                              client.Client

	configCache *[]byte

	ctx context.Context
}

// NewAzClient returns an Azure Client
func NewAzClient(subscriptionID string, resourceGroupName string, fwPolicyName string, fwPolicyRuleCollectionGroupName string, fwPolicyRuleCollectionGroupPriority int32, clientID string, client client.Client) AzClient {
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
	fwPolicyClient, err := a.NewFirewallPoliciesClient(string(subscriptionID), cred, nil)
	if err != nil {
		klog.Error("failed to create Firewall Policy client: %v", err)
	}
	az := &azClient{
		fwPolicyClient:                    fwPolicyClient,
		fwPolicyRuleCollectionGroupClient: n.NewFirewallPolicyRuleCollectionGroupsClientWithBaseURI(settings.Environment.ResourceManagerEndpoint, string(subscriptionID)),
		ipGroupClient:                     ipGroupClient,
		clientID:                          clientID,

		subscriptionID:                      subscriptionID,
		resourceGroupName:                   resourceGroupName,
		fwPolicyName:                        fwPolicyName,
		fwPolicyRuleCollectionGroupName:     fwPolicyRuleCollectionGroupName,
		fwPolicyRuleCollectionGroupPriority: fwPolicyRuleCollectionGroupPriority,
		firewallPolicyLoc:                   "",
		queue:                               NewQueue("policyBuilder"),
		client:                              client,

		configCache: to.ByteSlicePtr([]byte{}),

		ctx: context.Background(),
	}

	worker := NewWorker(az.queue, az.client)
	go worker.DoWork()

	return az
}

func (az *azClient) SetAuthorizer(authorizer autorest.Authorizer) {
	az.fwPolicyRuleCollectionGroupClient.Authorizer = authorizer
}

func (az *azClient) UpdateFirewallPolicy(ctx context.Context, req ctrl.Request) (err error) {
	az.checkIfJobToBeAddedToChannel(ctx, req)

	return
}

func (az *azClient) checkIfJobToBeAddedToChannel(ctx context.Context, req ctrl.Request) (err error) {
	az.queue.AddJob(Job{
		Request:  req,
		ctx:      ctx,
		AzClient: az,
	})
	return
}

func (az *azClient) processRequest(ctx context.Context, req ctrl.Request, nodesWithFwTaint []*corev1.Node) (err error) {
	processEventStart := time.Now()

	var erulesSourceAddresses = make(map[string][]string)
	var ipGroupIds = make(map[string]string)
	erulesList := &egressv1.EgressrulesList{}
	listOpts := []client.ListOption{}
	if err := az.client.List(ctx, erulesList, listOpts...); err != nil {
		return err
	}

	nodeList := &corev1.NodeList{}
	if err := az.client.List(ctx, nodeList, []client.ListOption{}...); err != nil {
		return err
	}

	//fetch all the Ip groups in a resource group
	var ipGroupsInRG = make(map[string]*a.IPGroup)
	res1 := az.ipGroupClient.NewListByResourceGroupPager(az.resourceGroupName, nil)
	for res1.More() {
		page, err := res1.NextPage(ctx)
		if err != nil {
			klog.Error("failed to advance page: %v", err)
		}
		for _, ipGroup := range page.Value {
			ipGroupsInRG[*ipGroup.Name] = ipGroup
		}
	}

	for _, item := range erulesList.Items {
		for _, egressrule := range item.Spec.EgressRules {
			var sourceIpGroups []string
			if egressrule.NodeSelector != nil {
				for _, m := range egressrule.NodeSelector {
					for k, v := range m {
						IPGroupName := IpGroupNamePrefix + k + v
						if ipGroupIds[IPGroupName] == "" {
							sourceAddress := getSourceAddressesByNodeLabels(k, v, *nodeList)
							var id = ""

							//check if IP Group already exists
							if _, ok := ipGroupsInRG[IPGroupName]; ok {
								addressesInIpGroup := ipGroupsInRG[IPGroupName].Properties.IPAddresses
								IPGroupProvisioningState := *ipGroupsInRG[IPGroupName].Properties.ProvisioningState
								if len(sourceAddress) == len(addressesInIpGroup) && !checkIfElementsPresentInArray(sourceAddress, addressesInIpGroup) {
									//IP group not changed
									id = *ipGroupsInRG[IPGroupName].ID
								} else if IPGroupProvisioningState == a.ProvisioningStateUpdating && pollers[IPGroupName] != nil {
									//if the IP group is in updating state, wait for it to complete.
									klog.Info("Waiting for the Ip group update to complete, ", IPGroupName)
									_, err = pollers[IPGroupName].PollUntilDone(ctx, nil)
								}
							}

							// update IP Group and get the associated ID.
							if id == "" {
								poller := az.updateIpGroup(sourceAddress, IPGroupName)
								pollers[IPGroupName] = poller
								res, err1 := az.ipGroupClient.Get(az.ctx, az.resourceGroupName, IPGroupName, &a.IPGroupsClientGetOptions{Expand: nil})
								if err1 != nil {
									klog.Error("Failed to get the IP Group", err1)
								}
								id = *res.IPGroup.ID
							}
							ipGroupIds[IPGroupName] = id
						}
						sourceIpGroups = append(sourceIpGroups, ipGroupIds[IPGroupName])
					}
				}
			}
			erulesSourceAddresses[egressrule.Name] = sourceIpGroups
		}
	}

	go az.WaitForNodeIpGroupUpdate(ctx, nodesWithFwTaint, pollers)

	//Generate fw config
	az.BuildPolicy(*erulesList, erulesSourceAddresses)

	duration := time.Now().Sub(processEventStart)
	klog.Infof("Completed last event loop run in: %+v", duration)
	return
}

func (az *azClient) updateIpGroup(sourceAddress []*string, ipGroupsName string) *runtime.Poller[a.IPGroupsClientCreateOrUpdateResponse] {
	poller, err := az.ipGroupClient.BeginCreateOrUpdate(az.ctx, az.resourceGroupName, ipGroupsName, a.IPGroup{
		Location: to.StringPtr(az.firewallPolicyLoc),
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
			Priority:        to.Int32Ptr(az.fwPolicyRuleCollectionGroupPriority),
			RuleCollections: ruleCollections,
		}),
	}

	if az.configIsSame(fwRuleCollectionGrpObj) {
		klog.Info("cache: Config has NOT changed! No need to connect to ARM.")
		return
	}

	configJSON, _ := dumpSanitizedJSON(fwRuleCollectionGrpObj)
	klog.Infof("Generated config:\n%s", string(configJSON))

	//Poll for policy provisioning state and update the policy if the provisioning state is not "Updating"
	isPolicyInUpdatingState := false
	for {
		fwPolicyObj, err := az.fwPolicyClient.Get(az.ctx, string(az.resourceGroupName), az.fwPolicyName, &a.FirewallPoliciesClientGetOptions{Expand: nil})
		if err != nil || *fwPolicyObj.Properties.ProvisioningState != a.ProvisioningStateUpdating {
			break
		} else {
			if !isPolicyInUpdatingState {
				klog.Info("FW Policy is in the Updating state, waiting for the update to complete.....")
				isPolicyInUpdatingState = true
			}
		}
	}

	// Initiate deployment
	klog.Info("BEGIN firewall policy deployment")
	fwRuleCollectionGrp, err1 := az.fwPolicyRuleCollectionGroupClient.CreateOrUpdate(az.ctx, string(az.resourceGroupName), az.fwPolicyName, az.fwPolicyRuleCollectionGroupName, *fwRuleCollectionGrpObj)

	err1 = fwRuleCollectionGrp.WaitForCompletionRef(az.ctx, az.fwPolicyRuleCollectionGroupClient.BaseClient.Client)

	// Cache Phase //
	// ----------- //
	if err1 != nil {
		az.configCache = nil
		klog.Error("Error updating the Firewall Policy: ", err1)
		return
	}

	klog.Info("cache: Updated with latest applied config.")
	az.updateCache(fwRuleCollectionGrpObj)

	klog.Info("Applied generated firewall policy configuration.....")
	return
}

func (az *azClient) FetchFirewallPolicyLocation() string {
	fwPolicyObj, err := az.fwPolicyClient.Get(az.ctx, string(az.resourceGroupName), az.fwPolicyName, &a.FirewallPoliciesClientGetOptions{Expand: nil})

	if err != nil {
		klog.Error("Firewall Policy not found", err)
	} else {
		az.firewallPolicyLoc = *fwPolicyObj.Location
	}
	return az.firewallPolicyLoc
}
