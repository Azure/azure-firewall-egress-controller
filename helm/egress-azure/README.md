# Install Azure Firewall Egress Controller as a Helm Chart

1. Install Helm chart

```console
helm install [RELEASE_NAME] oci://mcr.microsoft.com/azfw/helmchart/afec --version 0.1.0 \
         --debug \
         --set fw.fwResourceGroup=<resourceGroup> \
         --set fw.subscriptionId=<subscriptionId> \
         --set fw.policyName=<azureFirewallPolicy> \
         --set fw.policyRuleCollectionGroup=<azureFirewallRuleCollectiongroup> \
         --set fw.policyRuleCollectionGroupPriority=<azureFirewallRuleCollectiongroupPriority> \
         --set auth.tenantId=<azureTenantId> \
         --set auth.clientId=<azureClientId> \
         --set auth.clientSecret=<azureClientSecret>
```

2. To upgrade the chart:

```console
helm upgrade [RELEASE_NAME] oci://mcr.microsoft.com/azfw/helmchart/afec --version [LATEST_VERSION] \
         --debug \
         --set fw.fwResourceGroup=<resourceGroup> \
         --set fw.subscriptionId=<subscriptionId> \
         --set fw.policyName=<azureFirewallPolicy> \
         --set fw.policyRuleCollectionGroup=<azureFirewallRuleCollectiongroup> \
         --set fw.policyRuleCollectionGroupPriority=<azureFirewallRuleCollectiongroupPriority> \
         --set auth.tenantId=<azureTenantId> \
         --set auth.clientId=<azureClientId> \
         --set auth.clientSecret=<azureClientSecret>
```

4. Check the log of the newly created pod to verify if it started properly.