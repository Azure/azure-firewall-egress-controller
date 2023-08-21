package azure

import (
	"testing"
	"encoding/json"
	"strings"

	azurefirewallrulesv1 "github.com/Azure/azure-firewall-egress-controller/pkg/api/v1"
	n "github.com/Azure/azure-sdk-for-go/services/network/mgmt/2021-03-01/network"
	"github.com/Azure/go-autorest/autorest/to"
)

func TestBuildFirewallConfig(t *testing.T) {
	erulesList := azurefirewallrulesv1.AzureFirewallRulesList{
		Items: []azurefirewallrulesv1.AzureFirewallRules{
			{
				Spec: azurefirewallrulesv1.AzureFirewallRulesSpec{
					EgressRules: []azurefirewallrulesv1.AzureFirewallEgressRulesSpec{
						{
							Name: "test1",
							NodeSelector: []map[string]string{
								{
									"app": "service",
								},
							},
							Rules: []azurefirewallrulesv1.AzureFirewallEgressrulesRulesSpec{
								{
									RuleCollectionName: "aks-fw-ng-allow",
									Priority:           210,
									RuleName:           "rule1",
									TargetFqdns:        []string{"*.google.com"},
									Protocol:           []string{"HTTP:80"},
									Action:             "Allow",
									RuleType:           "Application",
								},
								{
									RuleCollectionName: "aks-fw-ng-allow",
									Priority:           210,
									RuleName:           "rule2",
									TargetUrls:        []string{"www.microsoft.com"},
									Protocol:           []string{"HTTPs:443"},
									Action:             "Allow",
									RuleType:           "Application",
								},
								{
									RuleCollectionName: "aks-fw-ng",
									Priority:           200,
									RuleName:           "rule3",
									TargetFqdns:        []string{"*.yahoo.com"},
									Protocol:           []string{"HTTP:443"},
									Action:             "Deny",
									RuleType:           "Application",
								},
								{
									RuleCollectionName: "aks-fw-ng-network",
									Priority:           110,
									RuleName:           "rule4",
									DestinationFqdns: 	[]string{"*"}, 
									DestinationPorts: 	[]string{"*"},
									Protocol : 			[]string{"TCP","UDP","ICMP","ANY"}, 
									Action : 			"Allow",
									RuleType: 			"Network",
								},
								{
									RuleCollectionName: "aks-fw-ng-network",
									Priority:           110,
									RuleName:           "rule5",
									DestinationAddresses: 	[]string{"*"}, 
									DestinationPorts: 	[]string{"*"},
									Protocol : 			[]string{"TCP","UDP","ICMP","ANY"}, 
									Action : 			"Allow",
									RuleType: 			"Network",
								},
							},
						},
					},
				},
			},
		},
	}

	erulesSourceAddresses := map[string][]string{
		"test1": []string{"/subscriptions/7a06e974-7329-4485-87e7-3211b06c15aa/resourceGroups/afc-controller-setup-rg/providers/Microsoft.Network/ipGroups/IPGroup-node-appservice"},
	}

	expected := 
`{
--    "properties": {
--        "priority": 300,
--        "ruleCollections": [
--            {
--                "action": {
--                    "type": "Allow"
--                },
--                "name": "aks-fw-ng-allow",
--                "priority": 210,
--                "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
--                "rules": [
--                    {
--                        "destinationAddresses": [],
--                        "name": "rule1",
--                        "protocols": [
--                            {
--                                "port": 80,
--                                "protocolType": "Http"
--                            }
--                        ],
--                        "ruleType": "ApplicationRule",
--                        "sourceIpGroups": [
--                            "/subscriptions/7a06e974-7329-4485-87e7-3211b06c15aa/resourceGroups/afc-controller-setup-rg/providers/Microsoft.Network/ipGroups/IPGroup-node-appservice"
--                        ],
--                        "targetFqdns": [
--                            "*.google.com"
--                        ],
--                        "targetUrls": [],
--                        "terminateTLS": false
--                    },
--                    {
--                        "destinationAddresses": [],
--                        "name": "rule2",
--                        "protocols": [
--                            {
--                                "port": 443,
--                                "protocolType": "Https"
--                            }
--                        ],
--                        "ruleType": "ApplicationRule",
--                        "sourceIpGroups": [
--                            "/subscriptions/7a06e974-7329-4485-87e7-3211b06c15aa/resourceGroups/afc-controller-setup-rg/providers/Microsoft.Network/ipGroups/IPGroup-node-appservice"
--                        ],
--                        "targetFqdns": [],
--                        "targetUrls": [
--                            "www.microsoft.com"
--                        ],
--                        "terminateTLS": true
--                    }
--                ]
--            },
--            {
--                "action": {
--                    "type": "Deny"
--                },
--                "name": "aks-fw-ng",
--                "priority": 200,
--                "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
--                "rules": [
--                    {
--                        "destinationAddresses": [],
--                        "name": "rule3",
--                        "protocols": [
--                            {
--                                "port": 443,
--                                "protocolType": "Http"
--                            }
--                        ],
--                        "ruleType": "ApplicationRule",
--                        "sourceIpGroups": [
--                            "/subscriptions/7a06e974-7329-4485-87e7-3211b06c15aa/resourceGroups/afc-controller-setup-rg/providers/Microsoft.Network/ipGroups/IPGroup-node-appservice"
--                        ],
--                        "targetFqdns": [
--                            "*.yahoo.com"
--                        ],
--                        "targetUrls": [],
--                        "terminateTLS": false
--                    }
--                ]
--            },
--            {
--                "action": {
--                    "type": "Allow"
--                },
--                "name": "aks-fw-ng-network",
--                "priority": 110,
--                "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
--                "rules": [
--                    {
--                        "destinationAddresses": [],
--                        "destinationFqdns": [
--                            "*"
--                        ],
--                        "destinationPorts": [
--                            "*"
--                        ],
--                        "ipProtocols": [
--                            "TCP",
--                            "UDP",
--                            "ICMP",
--                            "Any"
--                        ],
--                        "name": "rule4",
--                        "ruleType": "NetworkRule",
--                        "sourceIpGroups": [
--                            "/subscriptions/7a06e974-7329-4485-87e7-3211b06c15aa/resourceGroups/afc-controller-setup-rg/providers/Microsoft.Network/ipGroups/IPGroup-node-appservice"
--                        ]
--                    },
--                    {
--                        "destinationAddresses": [
--                            "*"
--                        ],
--                        "destinationFqdns": [],
--                        "destinationPorts": [
--                            "*"
--                        ],
--                        "ipProtocols": [
--                            "TCP",
--                            "UDP",
--                            "ICMP",
--                            "Any"
--                        ],
--                        "name": "rule5",
--                        "ruleType": "NetworkRule",
--                        "sourceIpGroups": [
--                            "/subscriptions/7a06e974-7329-4485-87e7-3211b06c15aa/resourceGroups/afc-controller-setup-rg/providers/Microsoft.Network/ipGroups/IPGroup-node-appservice"
--                        ]
--                    }
--                ]
--            }
--        ]
--    }
--}`

	ruleCollections := BuildFirewallConfig(erulesList, erulesSourceAddresses)

	fwRuleCollectionGrpObj := &n.FirewallPolicyRuleCollectionGroup{
		FirewallPolicyRuleCollectionGroupProperties: &(n.FirewallPolicyRuleCollectionGroupProperties{
			Priority:        to.Int32Ptr(300),
			RuleCollections: ruleCollections,
		}),
	}

	jsonBlob, err := fwRuleCollectionGrpObj.MarshalJSON()
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	var into map[string]interface{}
	err = json.Unmarshal(jsonBlob, &into)
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	jsonBlob, err = json.MarshalIndent(into, "--", "    ")
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	jsonTxt := string(jsonBlob)

	linesAct := strings.Split(jsonTxt, "\n")
	linesExp := strings.Split(expected, "\n")

	if len(linesAct)!=len(linesExp) {
		t.Errorf("Line counts are different: Expected %d but got: %d", len(linesExp), len(linesAct))
	}

			
	for idx, line := range linesAct {
		curatedLineAct := strings.Trim(line, " ")
		curatedLineExp := strings.Trim(linesExp[idx], " ")
		if curatedLineAct != curatedLineExp {
			t.Errorf("Lines at index %d are different:\n%s\nvs expected:\n%s\nActual JSON:\n%s\nExpected JSON\n%s\n", idx, curatedLineAct, curatedLineExp, jsonTxt, expected)
		}
	}
}
