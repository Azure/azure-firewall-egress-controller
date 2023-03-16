# Install Azure Firewall Egress Controller as a Helm Chart

1. Add the `afec-helm` helm repo and perform a helm update

```console
helm repo add afec-helm oci://mcr.microsoft.com/azfw/helmchart/afec
helm repo update
```

2. Install Helm chart `afec-helm`

```console
helm install [RELEASE_NAME] afec-helm \
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
helm upgrade [RELEASE_NAME] afec-helm \
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