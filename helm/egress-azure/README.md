# Install Azure Firewall Egress Controller as a Helm Chart

1. Add the `azure-firewall-egress-controller` helm repo and perform a helm update

```console
helm repo add azure-firewall-egress-controller https://azure.github.io/azure-firewall-egress-controller/charts
helm repo update
```

2. Install Helm chart `azure-firewall-egress-controller`

```console
helm install [RELEASE_NAME] azure-firewall-egress-controller/egress-azure \
         --debug \
         --set fw.fwResourceGroup=<resourceGroup> \
         --set fw.subscriptionId=<subscriptionId> \
         --set fw.policyName=<azureFirewallPolicy> \
         --set fw.policyRuleCollectionGroup=<azureFirewallRuleCollectiongroup> \
         --set auth.tenantId=<azureTenantId> \
         --set auth.clientId=<azureClientId> \
         --set auth.clientSecret=<azureClientSecret>
```

3. To upgrade the chart:

```console
helm upgrade [RELEASE_NAME] azure-firewall-egress-controller/egress-azure \
         --debug \
         --set fw.fwResourceGroup=<resourceGroup> \
         --set fw.subscriptionId=<subscriptionId> \
         --set fw.policyName=<azureFirewallPolicy> \
         --set fw.policyRuleCollectionGroup=<azureFirewallRuleCollectiongroup> \
         --set auth.tenantId=<azureTenantId> \
         --set auth.clientId=<azureClientId> \
         --set auth.clientSecret=<azureClientSecret>
```

4. Check the log of the newly created pod to verify if it started properly.
