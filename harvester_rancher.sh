#!/usr/bin/env bash
# this does something with Rancher and Harester

# rancher url
rancher_url=rancher.rfed.io

# harvester vip/url
harvester_url=192.168.1.4

# get rancher token
token=$(curl -sk -X POST https://$rancher_urlv3-public/localProviders/local?action=login -H 'content-type: application/json' -d '{"username":"admin","password":"Pa22word"}' | jq -r .token)

# create havester connection
curl -sk https://$rancher_urlv1/provisioning.cattle.io.clusters -H "Authorization: Bearer $token" -X POST -H 'content-type: application/json' -d '{"type":"provisioning.cattle.io.cluster","metadata":{"namespace":"fleet-default","name":"ms01","labels":{"provider.cattle.io":"harvester"}},"cachedHarvesterClusterVersion":"","spec":{"agentEnvVars":[]}}'

# get client url
client_url=$(kubectl get clusterregistrationtokens.management.cattle.io -n $(kubectl  get ns | grep "c-m" | awk '{ print $1}') default-token -o json | jq -r .status.manifestUrl)

# get harvester token
token=$(curl -sk -X POST https://$harvester_url/v3-public/localProviders/local?action=login -H 'content-type: application/json' -d '{"username":"admin","password":"Pa22word"}' | jq -r .token)

# get kubeconfig for harvester
curl -sk https://$harvester_url/v1/management.cattle.io.clusters/local?action=generateKubeconfig -H "Authorization: Bearer $token" -X POST -H 'content-type: application/json' | jq -r .config > $harvester_url.yaml

# use kubeconfig for creating url
export KUBECONFIG=$harvester_url.yaml

# apply it
cat <<EOF | kubectl --insecure-skip-tls-verify apply -f -  > /dev/null 2>&1
apiVersion: harvesterhci.io/v1beta1
kind: Setting
metadata:
  name: cluster-registration-url
status:
value: $client_url
EOF

# clean up
unset KUBECONFIG
rm -rf $harvester_url.yaml

