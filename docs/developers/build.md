# AFEC Deployment

The Azure Firewall Egress Controller (AFEC) is a pod within your Kubernetes cluster.
AFEC monitors a subset of Kubernetes Resources and translates them to Azure Firewall specific configuration and applies to the  [Azure Resource Manager (ARM)](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-overview).

### Outline:
- [Prerequisites](#prerequisites)
- [Azure Resource Manager Authentication (ARM)](#azure-resource-manager-authentication)
    - Option 1: [Using a Service Principal](#using-a-service-principal)
- [Install Azure Firewall Egress Controller using Helm](#install-azure-firewall-egress-controller-as-a-helm-chart)

### Prerequisites
This documents assumes you already have the following tools and infrastructure installed:
- Azure Firewall as the next hop to the AKS cluster. Please follow [this](https://learn.microsoft.com/en-us/azure/aks/limit-egress-traffic) documentation for this setup.
- Create an Active Directory Service Principal.
- `az` CLI, `kubectl`, and `helm` installed. These tools are required for the commands below.

### Azure Resource Manager Authentication

AFEC communicates with the Kubernetes API server and the Azure Resource Manager. It requires an identity to access
these APIs.

### Using a Service Principal
AFEC access to ARM can be possible by creating service principal. Follow the steps below to create an Azure Active Directory (AAD) service principal object.

  1. Create an Active Directory Service Principal and make sure the created service principal has contributor access to the Azure Firewall.

  ```bash
  az ad sp create-for-rbac --role Contributor --scopes /subscriptions/policysubscriptionId
  ```

  Please record the appId (`<azureClientId>`), password(`<azureClientSecret>`), and tenant(`<azureTenantId>`) values - these will be used in the following steps to authenticate to azure.

## Install Azure Firewall Egress Controller as a Helm Chart
[Helm](https://docs.microsoft.com/en-us/azure/aks/kubernetes-helm) is a package manager for
Kubernetes. We will leverage it to install the `azure-firewall-egress-controller` package.
Use [Cloud Shell](https://shell.azure.com/) to install install the AFEC Helm package:

1. Add the `afec-helm` helm repo and perform a helm update

```console
helm repo add afec-helm oci://mcr.microsoft.com/azfw/helmchart/afec
helm repo update
```

2. Install Helm chart `afec-helm`

```console
helm install [RELEASE_NAME] afec-helm \
         --debug \
         --set fw.policyResourceId=<fwpolicyResourceId> \
         --set fw.policyResourceGroup=<fwpolicyResourceGroup> \
         --set fw.policysubscriptionId=<fwpolicySubscriptionId> \
         --set fw.policyName=<fwPolicyName> \
         --set fw.policyRuleCollectionGroup=<fwPolicyRuleCollectionGroup> \
         --set auth.tenantId=<azureTenantId> \
         --set auth.clientId=<azureClientId> \
         --set auth.clientSecret=<azureClientSecret>
```
`<azureTenantId>` and `<azureClientId>` and `<azureClientSecret>` are values that were created in the previous section.
If a Firewall Policy Resource Id is provided, individual fields of fwpolicySubscriptionId, fwpolicyResourceGroup and fwPolicyName will be ignored

#### Parameters
- `<fwpolicyResourceId>` : ID of the Firewall Policy.
- `<fwpolicyResourceGroup>` : Name of the Azure Resource group in which Azure Firewall Policy was created.
- `<fwpolicySubscriptionId>` : The Azure Subscription ID in which Azure Firewall Policy resides. Example: `a123b234-a3b4-557d-b2df-a0bc12de1234`
- `<fwPolicyName>` : Name of the Azure Firewall Policy that is attached to the firewall.
- `<fwPolicyRuleCollectionGroup>` : The Rule Collection Group in the Firewall Policy dedicated to the Egress Controller.
- `<azureTenantId>` : The tenant ID of the Identity.
- `<azureClientId>` : The client ID of the Identity.
- `<azureClientSecret>` : The client Secret of the Identity.


3. To upgrade the chart

```console
helm upgrade [RELEASE_NAME] afec-helm \
         --debug \
         --set fw.policyResourceId=<fwpolicyResourceId> \
         --set fw.policyResourceGroup=<fwpolicyResourceGroup> \
         --set fw.policysubscriptionId=<fwpolicySubscriptionId> \
         --set fw.policyName=<fwPolicyName> \
         --set fw.policyRuleCollectionGroup=<fwPolicyRuleCollectionGroup> \
         --set auth.tenantId=<azureTenantId> \
         --set auth.clientId=<azureClientId> \
         --set auth.clientSecret=<azureClientSecret>
```

4. Check the log of the newly created pod to verify if it started properly.
