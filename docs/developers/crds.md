### Custom Resource Definition (CRD)  
A resource is an endpoint in the Kubernetes API that stores a collection of API objects a certain kind; for example, the built-in pods resource contains a collection of Pod objects. A custom resource is an extension of the Kubernetes API that is not necessarily available in a default Kubernetes installation. It represents a customization of a particular Kubernetes installation. 

### The AzureFirewallRules Resource: 

The AzureFirewallRules format which is a cluster-scoped CustomResourceDefinition allows us define configuration for the egress traffic and deploy it to the cluster. 

#### The raw specification of the resource in Go looks like this: 
 
```bash
// AzureFirewallRules is the Schema for the azureFirewallRules API
type AzureFirewallRules struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

  // AzureFirewallRulesSpec defines the desired state of azureFirewallRules
	Spec   AzureFirewallRulesSpec   `json:"spec,omitempty"`
  // AzureFirewallRulesStatus defines the observed state of azureFirewallRules
	Status AzureFirewallRulesStatus `json:"status,omitempty"`
}
```

#### An example AzureFirewallRules might look like this: 

```bash
apiVersion: egress.azure-firewall-egress-controller.io/v1 
kind: AzureFirewallRules 
metadata: 
  name: egressrules-sample1 
spec: 
  egressRules: 
    - name: "test-egress-rule-1" 
      nodeSelector: 
        - app: "nginx0" 
      rules: 
        - ruleName: "rule1" 
          ruleCollectionName: "aks-fw-ng-network" 
          priority: 110 
          destinationFqdns: ["*"] 
          destinationPorts: ["*"] 
          protocol : ["TCP","UDP"] 
          action : "Allow" 
          ruleType: "Network" 
        - ruleName: "rule2" 
          ruleCollectionName: "aks-fw-ng" 
          priority: 200 
          targetFqdns: ["*.yahoo.com"] 
          protocol : ["HTTP:80"] 
          action : "Deny" 
          ruleType: "Application"
    - name: "test-egress-rule-2" 
      nodeSelector: 
        - nodepool1: "set1"
        - nodepool2: "set1"
      rules: 
        - ruleName: "rule3" 
          ruleCollectionName: "aks-fw-ng" 
          priority: 200 
          targetFqdns: ["*.yahoo.com"] 
          protocol : ["HTTP:80"] 
          action : "Deny" 
          ruleType: "Application" 
```
**Mandatory Fields**: As with all other Kubernetes config, a AzureFirewallRules needs `apiVersion`, `Kind`, and `metadata` fields. `metadata` field includes the name of the policy and the set of labels to identify the resources in Kubernetes.<br>

**spec**: Egressrules spec has all the information needed to define rules on Azure Firewall.

**egressRules**: egressRules field allows us to define list of egress rules on the nodes using the labels asigned to them. This field will allow us to have multiple rules on different node selectors. The example shown above defines two egressRules `test-egress-rule-1` and `test-egress-rule-2`. And the rules defined in `test-egress-rule-1` will be applied to nodes that match label "app=nginx0" and the rules in ``test-egress-rule-2` will be applied to nodes with label "nodepool1=set1" and "nodepool2=set1".

**nodeSelector**: nodeSelector is a list of node labels to which the rules should apply. In the above example, we defined the nodeSelector with the label "app=nginx0" All the nodes that are grouped using this nodeSelector label will adhere to those rules.

**rules**: rules field allows us define list of azure firewall rules that the nodes grouped using this nodeSelector label should follow.
- `ruleName`, `ruleCollectionName`, `priority`, `protocol`, `action`, `ruleType` are the mandatory fields in rules section.
- Two rule types are supported in the AzureFirewallRules - `Application` and `Network`.

| Field  |Description                                                                                                                                                                           |
|------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ruleName                                 | Name of the rule                                                                                                                                                                      |
| ruleCollectionName                       | Rule Collection to which the rule should belong.                                                                                                                                      |
| priority                                 | The priority value of the rule collection, determines order the rule collections are processed.                                                                                       |
| action                                   | Rule Collection action. Applies to all the rules in the rule collection.<br>Supported Values: "Allow" or "Deny"                                                                       |
| ruleType                                 | Supported rule types: "Application" or "Network"                                                                                                                                          |
| protocol                                 | Defines the protocol that should be used to filter the traffic.<br>Examples: <br>Application rule: ["https:80","http:443"]<br>Network rule: ["TCP"], ["TCP","UDP"], ["ICMP"], ["ANY"] |
| targetFqdns<br>targetUrls                | Supported destination types for a Application rule.  Specifies the list of destination fqdns or urls that should be used to filter the traffic.                                                                                                                                 |
| destinationAddresses<br>destinationFqdns | Supported destination types for a Network rule. Specifies the list of destination addresses or fqdns that should be used to filter the trafficrule.                                                                                                                                       |
| destinationPorts                         | List of destination ports that should be used to filter the traffic in a network rule.                                                                                                                  |

**Examples of Application Rule Type:** <br>

1. The following example allows the egress traffic from nodes with label "app=service" to *.google.com.
```bash
apiVersion: egress.azure-firewall-egress-controller.io/v1 
kind: AzureFirewallRules 
metadata: 
  name: egressrules-sample1 
spec: 
  egressRules: 
    - name: "Allow-google" 
      nodeSelector: 
        - app: "service"
      rules: 
        - ruleName: "rule1" 
          ruleCollectionName: "aks-fw-ng-allow" 
          priority: 210 
          targetFqdns: ["*.google.com"] 
          protocol : ["HTTP:80"] 
          action : "Allow" 
          ruleType: "Application" 
```

**Examples of Network Rule Type:**<br>
1. The following example allows egress traffic from nodes with label "role=db" to destination addresses "10.0.0.1" and "10.0.0.2" on any port using TCP.

```bash
apiVersion: egress.azure-firewall-egress-controller.io/v1 
kind: AzureFirewallRules 
metadata: 
  name: egressrules-sample1 
spec: 
  egressRules: 
    - name: "Allow-addresses" 
      nodeSelector: 
        - role: "db"
      rules: 
        - ruleName: "rule1" 
          ruleCollectionName: "aks-fw-ng-network" 
          priority: 110 
          destinationAddresses: ["10.0.0.1", "10.0.0.2"] 
          destinationPorts: ["*"] 
          protocol : ["TCP"] 
          action : "Allow" 
          ruleType: "Network" 
```

2. We can have rules to allow/deny traffic to any destination.

```bash
apiVersion: egress.azure-firewall-egress-controller.io/v1 
kind: AzureFirewallRules 
metadata: 
  name: egressrules-sample1 
spec: 
  egressRules: 
    - name: "Allow-web" 
      nodeSelector: 
        - app: "service"
      rules: 
        - ruleName: "rule1" 
          ruleCollectionName: "aks-fw-ng-network" 
          priority: 110 
          destinationAddresses: ["*"] 
          destinationPorts: ["80","443"] 
          protocol : ["TCP"] 
          action : "Allow" 
          ruleType: "Network" 
```

3. We can have combination of network and application rules in just one resource.

```bash
apiVersion: egress.azure-firewall-egress-controller.io/v1 
kind: AzureFirewallRules 
metadata: 
  name: egressrules-sample1 
spec: 
  egressRules: 
    - name: "comb-network-application-rules" 
      nodeSelector: 
        - app: "nginx0" 
      rules: 
        - ruleName: "rule1" 
          ruleCollectionName: "aks-fw-ng-network-deny" 
          priority: 100 
          destinationFqdns: ["*"] 
          destinationPorts: ["*"] 
          protocol : ["TCP","UDP"] 
          action : "Deny" 
          ruleType: "Network" 
        - ruleName: "rule2" 
          ruleCollectionName: "aks-fw-ng" 
          priority: 200 
          targetFqdns: ["*.yahoo.com"] 
          protocol : ["HTTP:80"] 
          action : "Deny" 
          ruleType: "Application"
```

 

  

 

 