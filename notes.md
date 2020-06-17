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

### get tars - rke2

```bash
mkdir /root/rke2-artifacts && cd /root/rke2-artifacts/
curl -#OL https://github.com/rancher/rke2/releases/download/v1.24.3%2Brke2r1/rke2-images.linux-amd64.tar.zst
curl -#OL https://github.com/rancher/rke2/releases/download/v1.24.3%2Brke2r1/rke2.linux-amd64.tar.gz
curl -#OL https://github.com/rancher/rke2/releases/download/v1.24.3%2Brke2r1/sha256sum-amd64.txt
curl -#OL https://github.com/rancher/rke2-selinux/releases/download/v0.9.stable.1/rke2-selinux-0.9-1.el8.noarch.rpm
curl -#OL https://github.com/rancher/rke2-packaging/releases/download/v1.24.3%2Brke2r1.stable.0/rke2-common-1.24.3.rke2r1-0.x86_64.rpm

yum install -y container-selinux iptables libnetfilter_conntrack libnfnetlink libnftnl policycoreutils-python-utils rke2-common-1.24.3~rke2r1-0.el8.x86_64.rpm rke2-selinux-0.9-1.el8.noarch.rpm 

curl -sfL https://get.rke2.io --output install.sh
```

### on server

```bash
cd /root/rke2-artifacts/
useradd -r -c "etcd user" -s /sbin/nologin -M etcd -U
mkdir -p /etc/rancher/rke2/ /var/lib/rancher/rke2/server/manifests/;
echo -e "#disable: rke2-ingress-nginx\n#profile: cis-1.6\nselinux: false" > /etc/rancher/rke2/config.yaml; 
echo -e "---\napiVersion: helm.cattle.io/v1\nkind: HelmChartConfig\nmetadata:\n  name: rke2-ingress-nginx\n  namespace: kube-system\nspec:\n  valuesContent: |-\n    controller:\n      config:\n        use-forwarded-headers: true\n      extraArgs:\n        enable-ssl-passthrough: true" > /var/lib/rancher/rke2/server/manifests/rke2-ingress-nginx-config.yaml; 
INSTALL_RKE2_ARTIFACT_PATH=/root/rke2-artifacts sh install.sh 
systemctl enable rke2-server.service && systemctl start rke2-server.service

# wait and add link
export KUBECONFIG=/etc/rancher/rke2/rke2.yaml 
ln -s /var/lib/rancher/rke2/data/v1*/bin/kubectl  /usr/local/bin/kubectl

# get token on server
cat /var/lib/rancher/rke2/server/node-token
# will need this for the agents to join

```

### on agents

```bash
SERVERIP=142.93.179.101
token=K107d13b6508d78b91c81bf19c6179b3bd3c0d8c267b7c895d3fafd6d7eca76d9d3::server:078debaf13f07dfe1611526d9ceec385
mkdir -p /etc/rancher/rke2/ && echo "server: https://$SERVERIP:9345" > /etc/rancher/rke2/config.yaml && echo "token: "$token >> /etc/rancher/rke2/config.yaml

cd /root/rke2-artifacts/
INSTALL_RKE2_ARTIFACT_PATH=/root/rke2-artifacts INSTALL_RKE2_TYPE=agent sh install.sh && systemctl enable rke2-agent.service && systemctl start rke2-agent.service
```

## k3s air gapped

### get tars - k3s

```bash
# Get bits
curl -#OL https://github.com/k3s-io/k3s/releases/download/v1.21.10%2Bk3s1/k3s-airgap-images-amd64.tar
curl -#L https://get.k3s.io -o install.sh
curl -#OL https://github.com/k3s-io/k3s/releases/download/v1.21.10%2Bk3s1/k3s
chmod 755 ./k3s
chmod 755 ./install.sh

# move bits 
mkdir -p /var/lib/rancher/k3s/agent/images/ /var/lib/rancher/k3s/agent/images/
mv k3s /usr/local/bin/
mv k3s*.tar /var/lib/rancher/k3s/agent/images/

# install stuff?
dnf install -y container-selinux iptables libnetfilter_conntrack libnfnetlink libnftnl policycoreutils-python-utils

# install
INSTALL_K3S_SKIP_DOWNLOAD=true ./install.sh

```

## Rancher Air Gapped

### get tars - rancher

```bash
helm repo add rancher-latest https://releases.rancher.com/server-charts/latest
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm pull jetstack/cert-manager --version v1.8.0
helm pull rancher-latest/rancher
helm template ./cert-manager-<version>.tgz | awk '$1 ~ /image:/ {print $2}' | sed s/\"//g > ./rancher-images.txt
helm template rancher-2.6.5.tgz | awk '$1 ~ /image:/ {print $2}' | sed s/\"//g >> ./rancher-images.txt
sort -u rancher-images.txt -o rancher-images.txt

# download images
./rancher-save-images.sh --image-list ./rancher-images.txt
```

example of a multi-homed install

```
disable: rke2-ingress-nginx
#profile: cis-1.6
selinux: false
advertise-address: 192.168.13.1
node-ip: 192.168.13.1
node-external-ip: 192.168.13.1
```

Move the tar and shell script.

### loading the bits

```bash
# load into the registry
./rancher-load-images.sh --image-list ./rancher-images.txt --registry <REGISTRY.YOURDOMAIN.COM:PORT>

```

## STIG

```bash
profile: cis-1.6
selinux: true
write-kubeconfig-mode: 0640
use-service-account-credentials: true
kube-controller-manager-arg:
- "tls-min-version=VersionTLS12"
- "tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
kube-scheduler-arg:
- "tls-min-version=VersionTLS12"
- "tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
kube-apiserver-arg:
- "tls-min-version=VersionTLS12"
- "tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
- "authorization-mode=RBAC,Node"
- "anonymous-auth=false"
- "audit-policy-file=/etc/rancher/rke2/audit-policy.yaml"
- "audit-log-mode=blocking-strict"
kubelet-arg:
- "protect-kernel-defaults=true"



echo "Creating Auto Policy.."
cat <<EOT > /etc/rancher/rke2/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse
EOT


agent:

cat <<EOT >> /etc/rancher/rke2/config.yaml
node-name: $1
token-file: /etc/rancher/rke2/join_token
server: https://$3:9345
write-kubeconfig-mode: 0640
profile: cis-1.6
kube-apiserver-arg:
- "authorization-mode=RBAC,Node"
kubelet-arg:
- "protect-kernel-defaults=true"
EOT



echo "Adding Canal config file.."
cat >> /etc/NetworkManager/conf.d/rke2-canal.conf << EOF
[keyfile]
unmanaged-devices=interface-name:cali*;interface-name:flannel*
EOF
```