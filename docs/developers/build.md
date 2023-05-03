# AFEC Deployment

The Azure Firewall Egress Controller (AFEC) is a pod within your Kubernetes cluster.
AFEC monitors a subset of Kubernetes Resources and translates them to Azure Firewall specific configuration and applies to the  [Azure Resource Manager (ARM)](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-overview).

### Outline:
- [Prerequisites](#prerequisites)
- [Azure Resource Manager Authentication (ARM)](#azure-resource-manager-authentication)
    - Option 1: [Using a Service Principal](#using-a-service-principal)
- [Install Azure Firewall Egress Controller using Helm](#install-azure-firewall-egress-controller-as-a-helm-chart)

## Prerequisites
This documents assumes you already have the following tools and infrastructure installed:  
- Azure Firewall as the next hop to the AKS cluster. Please follow [this](https://learn.microsoft.com/en-us/azure/aks/limit-egress-traffic) documentation for the setup. Make sure to add additional rules in the firewall to allow node <-> api-server communication and also to allow access to images in the Microsoft Container Registry(MCR).  
- Create an Active Directory Service Principal.  
- If you are using [Azure Cloud Shell](https://shell.azure.com/) it has all the tools already installed. Launch your shell from shell.azure.com or by clicking the link: [Launch Azure Cloud Shell](https://shell.azure.com). If you choose to use another environment, please ensure the following command line tools are installed:  
  1. `az` - Azure CLI: [installation instructions](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest)  
  2. `kubectl` - Kubernetes command-line tool: [installation instructions](https://kubernetes.io/docs/tasks/tools/install-kubectl)  
  3. `helm` (version 3.7 or later) - Kubernetes package manager: [installation instructions](https://github.com/helm/helm/releases/latest)  

### Setup Kubernetes Credentials

For the following steps we need setup [kubectl](https://kubectl.docs.kubernetes.io/) command,
which we will use to connect to our new Kubernetes cluster. We will use `az` CLI to obtain credentials for Kubernetes.  

Get credentials for your newly deployed AKS ([read more](https://docs.microsoft.com/en-us/azure/aks/kubernetes-walkthrough#connect-to-the-cluster)):

```bash
az aks get-credentials --resource-group aksClusterResourceGroupName --name aksClusterName
```

### Deploying cert-manager
Validation Webhooks are implemented for the CRD. In order for the API server to communicate with the webhook component, the webhook requires a TLS certificate that the apiserver is configured to trust. We are using [cert-manager](https://github.com/cert-manager/cert-manager) for provisioning the certificates for the webhook.

cert-manager Installation ([read more](https://cert-manager.io/docs/installation/)):

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.11.0/cert-manager.yaml
```

## Azure Resource Manager Authentication

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
Kubernetes. This document uses Helm version 3.7 or later. We will leverage it to install the `azure-firewall-egress-controller` package.
Use [Cloud Shell](https://shell.azure.com/) to install install the AFEC Helm package:

1. Install Helm chart

```console
helm install [RELEASE_NAME] oci://mcr.microsoft.com/azfw/helmchart/afec --version [VERSION] \
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


2. To upgrade the chart

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
