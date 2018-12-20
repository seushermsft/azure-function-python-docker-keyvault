import logging
import json
import sys
import os

import azure.functions as func

from azure.keyvault import KeyVaultClient, KeyVaultAuthentication
from azure.common.credentials import ServicePrincipalCredentials


def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Main entry point for function.
    """
    logging.info('Python HTTP trigger function processed a request.')

    try:
        #response = getSecret("https://cseboulder.vault.azure.net/", "seushertest")
        response = getSecretFlexVolume("seushertest")
        return func.HttpResponse(response)
    except:
        response = f"Unexpected error: {sys.exc_info()[0]}."
        return func.HttpResponse(response, 500)


def getSecretFlexVolume(secretName: str) -> str:
    """
    Use this when accessing secrets via FlexVolumes (kvvolume)

    Run: kubectl create -f \
         https://raw.githubusercontent.com/Azure/kubernetes-keyvault-flexvol/master/deployment/kv-flexvol-installer.yaml
    Grant your SPN 'Get' access on secrets (spn is from /etc/kubernetes/azure.json)
    Deploy the container
    """
    with open(f"/kv/{secretName}", 'r') as secret_text:
        return secret_text.read()

def getSecret(vaultUri: str, name: str) -> str:
    """
    Gets a secret from Key Vault when using a Volume to mount /etc/kubernetes/azure.json
    """

    def auth_callback(server, resource, scope):
        credentials = getServicePrincipal()
        token = credentials.token
        return token['token_type'], token['access_token']

    client = KeyVaultClient(KeyVaultAuthentication(auth_callback))

    # Don't specify version (the 3rd param) so we get the latest
    secret_bundle = client.get_secret(vaultUri, name, "") 

    return secret_bundle.value


def getServicePrincipal() -> ServicePrincipalCredentials:
    """
    Reads the service principal used by AKS from disk
    """

    # This works because the Kubernetes yaml file specifies a 
    # volumeMount on the deployment to mount /etc/kubernetes/azure.json
    with open('/spn') as json_data:
            d = json.load(json_data)

            spn = ServicePrincipalCredentials(
                client_id = d["aadClientId"],
                secret = d["aadClientSecret"],
                tenant = d["tenantId"],
                resource = "https://vault.azure.net"
            )

            return spn
