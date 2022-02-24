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

## api for moving namespaces to projects

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

---

## adding CIS to RKE2

```bash
 # run on the server
 cp -f /usr/local/share/rke2/rke2-cis-sysctl.conf /etc/sysctl.d/60-rke2-cis.conf; 
 systemctl restart systemd-sysctl; 
 useradd -r -c "etcd user" -s /sbin/nologin -M etcd -U
```
---

## RKE2 Air Gapped

### get tars

```bash
mkdir /root/rke2-artifacts && cd /root/rke2-artifacts/
curl -OLs https://github.com/rancher/rke2/releases/download/v1.22.6%2Brke2r1/rke2-images.linux-amd64.tar.zst
curl -OLs https://github.com/rancher/rke2/releases/download/v1.22.6%2Brke2r1/rke2.linux-amd64.tar.gz
curl -OLs https://github.com/rancher/rke2/releases/download/v1.22.6%2Brke2r1/sha256sum-amd64.txt

dnf install -y container-selinux iptables libnetfilter_conntrack libnfnetlink libnftnl policycoreutils-python-utils

curl -sfL https://get.rke2.io --output install.sh
```

### on server

```bash
mkdir -p /etc/rancher/rke2/ /var/lib/rancher/rke2/server/manifests/;
echo -e "#disable: rke2-ingress-nginx\nprofile: cis-1.6\nselinux: true" > /etc/rancher/rke2/config.yaml; 
echo -e "---\napiVersion: helm.cattle.io/v1\nkind: HelmChartConfig\nmetadata:\n  name: rke2-ingress-nginx\n  namespace: kube-system\nspec:\n  valuesContent: |-\n    controller:\n      config:\n        use-forwarded-headers: true\n      extraArgs:\n        enable-ssl-passthrough: true" > /var/lib/rancher/rke2/server/manifests/rke2-ingress-nginx-config.yaml; 
INSTALL_RKE2_ARTIFACT_PATH=/root/rke2-artifacts sh install.sh && systemctl enable rke2-server.service && systemctl start rke2-server.service

# get token on server
cat /var/lib/rancher/rke2/server/node-token
# will need this for the agents to join

```

### on agents

```bash
mkdir -p /etc/rancher/rke2/ && echo "server: https://$SERVERIP:9345" > /etc/rancher/rke2/config.yaml && echo "token: "$token >> /etc/rancher/rke2/config.yaml

INSTALL_RKE2_ARTIFACT_PATH=/root/rke2-artifacts INSTALL_RKE2_TYPE=agent sh install.sh && systemctl enable rke2-agent.service && systemctl start rke2-agent.service

```


## Rancher Air Gapped

### get tars

```bash
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm fetch jetstack/cert-manager --version v1.5.1
helm template ./cert-manager-<version>.tgz | awk '$1 ~ /image:/ {print $2}' | sed s/\"//g >> ./rancher-images.txt
sort -u rancher-images.txt -o rancher-images.txt

# download images
./rancher-save-images.sh --image-list ./rancher-images.txt

```

Move the tar and shell script. 

### loading the bits

```bash
# load into the registry
./rancher-load-images.sh --image-list ./rancher-images.txt --registry <REGISTRY.YOURDOMAIN.COM:PORT>

```
