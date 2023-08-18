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
