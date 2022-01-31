# New page for rancher/rke2 notes

best notes ever!

## automated importing of clusters

```bash
password=Pa22word
rancherUrl=rancher.dockr.life
clusterName=newCluster
token=$(curl -sk -X POST https://$rancherUrl/v3-public/localProviders/local?action=login -H 'content-type: application/json' -d '{"username":"admin","password":"'$password'"}' | jq -r .token)

curl -sk https://$rancherUrl/v1/provisioning.cattle.io.clusters -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"type":"provisioning.cattle.io.cluster","metadata":{"namespace":"fleet-default","name":"'$clusterName'"},"spec":{}}' > /dev/null 2>&1 

clusterId=$( curl -sk https://$rancherUrl/apis/provisioning.cattle.io/v1/namespaces/fleet-default/clusters/$clusterName -H "Authorization: Bearer $token" | jq -r .status.clusterName)

curl -sk https://$rancherUrl/v3/clusterregistrationtokens -H 'content-type: application/json' -H "Authorization: Bearer $token"  | jq -r ' .data[] | select(.clusterId=="'$clusterId'") | .insecureCommand' 
```

## api for moving namepsaces to projects

```bash
## move NS to project
password=Pa22word
rancherUrl=rancher.dockr.life
projectName=newProject
clusterName=local
nameSpace=flask
unset projectId

# get Token
token=$(curl -sk -X POST https://$rancherUrl/v3-public/localProviders/local?action=login -H 'content-type: application/json' -d '{"username":"admin","password":"'$password'"}' | jq -r .token)

# If project
projectId=$(curl -sk https://$rancherUrl/v3/projects -H 'content-type: application/json' -H "Authorization: Bearer $token" | jq '.data[] | select(.name=="newProject") | .id')

# create project
if [ -z $projectId ]; then 
  projectId=$(curl -sk https://$rancherUrl/v3/projects -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"type":"project","name":"'$projectName'","annotations":{},"labels":{},"clusterId":"'$clusterName'"}' | jq -r .id | awk -F: '{print $2}')
fi

# get resource verison
resourceVersion=$(curl -sk https://$rancherUrl/api/v1/namespaces/$nameSpace -H 'content-type: application/json' -H 'accept: application/json' -H "Authorization: Bearer $token" |jq -r .metadata.resourceVersion)

# move NS to new project
curl -sk https://$rancherUrl/v1/namespaces/$nameSpace -H 'content-type: application/json' -H 'accept: application/json' -H "Authorization: Bearer $token" -X PUT  -d '{"id":"'$nameSpace'","metadata":{"annotations":{"field.cattle.io/projectId":"'$clusterName':'$projectId'"},"labels":{"field.cattle.io/projectId":"'$projectId'"},"name":"'$nameSpace'","resourceVersion": "'$resourceVersion'"}}'

```


## deploy monitoring

```bash
password=Pa22word
rancherUrl=rancher.dockr.life
clusterName=local

# get Token
token=$(curl -sk -X POST https://$rancherUrl/v3-public/localProviders/local?action=login -H 'content-type: application/json' -d '{"username":"admin","password":"'$password'"}' | jq -r .token)

curl -sk https://$rancherUrl/v1/catalog.cattle.io.clusterrepos/rancher-charts?action=install -H 'content-type: application/json' -H 'accept: application/json' -H "Authorization: Bearer $token" -d '{"charts":[{"chartName":"rancher-monitoring-crd","version":"100.1.0+up19.0.3","releaseName":"rancher-monitoring-crd","projectId":null,"values":{"global":{"cattle":{"clusterId":"local","clusterName":"local","systemDefaultRegistry":"","url":"https://'$rancherUrl'","rkePathPrefix":"","rkeWindowsPathPrefix":""},"systemDefaultRegistry":""}},"annotations":{"catalog.cattle.io/ui-source-repo-type":"cluster","catalog.cattle.io/ui-source-repo":"rancher-charts"}},{"chartName":"rancher-monitoring","version":"100.1.0+up19.0.3","releaseName":"rancher-monitoring","annotations":{"catalog.cattle.io/ui-source-repo-type":"cluster","catalog.cattle.io/ui-source-repo":"rancher-charts"},"values":{"ingressNginx":{"enabled":true,"namespace":"kube-system"},"prometheus":{"prometheusSpec":{"evaluationInterval":"1m","retentionSize":"50GiB","scrapeInterval":"1m"}},"rke2ControllerManager":{"enabled":true},"rke2Etcd":{"enabled":true},"rke2Proxy":{"enabled":true},"rke2Scheduler":{"enabled":true},"global":{"cattle":{"clusterId":"local","clusterName":"local","systemDefaultRegistry":"","url":"https://'$rancherUrl'","rkePathPrefix":"","rkeWindowsPathPrefix":""},"systemDefaultRegistry":""}}}],"noHooks":false,"timeout":"600s","wait":true,"namespace":"cattle-monitoring-system","projectId":null,"disableOpenAPIValidation":false,"skipCRDs":false}'
```
