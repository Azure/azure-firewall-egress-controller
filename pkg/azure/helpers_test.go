package azure

import (
	"testing"
	"strings"

	"github.com/Azure/go-autorest/autorest/to"
	n "github.com/Azure/azure-sdk-for-go/services/network/mgmt/2021-03-01/network"
)

func TestDumpSanitizedJSON(t *testing.T) {
	fwRuleCollectionGrp := &n.FirewallPolicyRuleCollectionGroup{
		FirewallPolicyRuleCollectionGroupProperties: &(n.FirewallPolicyRuleCollectionGroupProperties{
			Priority:        to.Int32Ptr(300),
		}),
	}

	expected := 
`{
--Azure FW config --    "properties": {
--Azure FW config --        "priority": 300
--Azure FW config --    }
--Azure FW config --}`

	jsonBlob, err := dumpSanitizedJSON(fwRuleCollectionGrp)
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

func TestConfigIsSame(t *testing.T) {
	az := &azClient{
		configCache: to.ByteSlicePtr([]byte{}),
	}
	config := &n.FirewallPolicyRuleCollectionGroup{
		FirewallPolicyRuleCollectionGroupProperties: &(n.FirewallPolicyRuleCollectionGroupProperties{
			Priority:        to.Int32Ptr(300),
		}),
	}

	isConfigSame := az.configIsSame(config)
	if isConfigSame!= false {
		t.Errorf("Expected %t, but got: %t", false, true);
	}

	az.updateCache(config)
	isConfigSame = az.configIsSame(config)
	if isConfigSame!= true {
		t.Errorf("Expected %t, but got: %t", true, false);
	}
}