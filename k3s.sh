#!/bin/bash
# https://github.com/clemenko/k3s/blob/master/k3s.sh
# this script assumes digitalocean is setup with DNS.
# you need doctl, kubectl, uuid, jq, k3sup, pdsh and curl installed.
# clemenko@gmail.com 

###################################
# edit vars
###################################
set -e
num=3
password=Pa22word
zone=nyc3
size=s-4vcpu-8gb
key=30:98:4f:c5:47:c2:88:28:fe:3c:23:cd:52:49:51:01
domain=dockr.life

#image=ubuntu-21-10-x64
image=rockylinux-8-x64

orchestrator=rke # no rke k3s rancher
k3s_channel=stable # latest
rke2_channel=v1.21

#stackrox automation.
export REGISTRY_USERNAME=AndyClemenko
version=latest

# Please set this before runing the script.
#export REGISTRY_PASSWORD=

# Linux or Darwin
roxOS=Darwin

######  NO MOAR EDITS #######
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
NORMAL=$(tput sgr0)
BLUE=$(tput setaf 4)

if [ "$image" = k3sos ]; then user=k3s; else user=root; fi
if [ "$orchestrator" = k3s ]; then prefix=k3s; else prefix=k3s; fi

#better error checking
command -v doctl >/dev/null 2>&1 || { echo "$RED" " ** Doctl was not found. Please install. ** " "$NORMAL" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "$RED" " ** Curl was not found. Please install. ** " "$NORMAL" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "$RED" " ** Jq was not found. Please install. ** " "$NORMAL" >&2; exit 1; }
command -v pdsh >/dev/null 2>&1 || { echo "$RED" " ** Pdsh was not found. Please install. ** " "$NORMAL" >&2; exit 1; }
command -v uuid >/dev/null 2>&1 || { echo "$RED" " ** Uuid was not found. Please install. ** " "$NORMAL" >&2; exit 1; }
command -v k3sup >/dev/null 2>&1 || { echo "$RED" " ** K3sup was not found. Please install. ** " "$NORMAL" >&2; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "$RED" " ** Kubectl was not found. Please install. ** " "$NORMAL" >&2; exit 1; }

if [ -f hosts.txt ]; then server=$(sed -n 1p hosts.txt|awk '{print $1}'); fi

################################# up ################################
function up () {
export PDSH_RCMD_TYPE=ssh
build_list=""
uuid=""
helm repo update > /dev/null 2>&1

if [ -f hosts.txt ]; then
  echo "$RED" "Warning - cluster already detected..." "$NORMAL"
  exit
fi

#rando list generation
for i in $(seq 1 $num); do
 uuid=$(uuid -v4| awk -F"-" '{print $4}')
 build_list="$prefix-$uuid $build_list"
done

#build VMS
echo -n " building vms - $build_list"
doctl compute droplet create $build_list --region $zone --image $image --size $size --ssh-keys $key --wait > /dev/null 2>&1
doctl compute droplet list|grep -v ID|grep $prefix|awk '{print $3" "$2}'> hosts.txt
echo "$GREEN" "ok" "$NORMAL"

#check for SSH
echo -n " checking for ssh "
for ext in $(awk '{print $1}' hosts.txt); do
  until [ $(ssh -o ConnectTimeout=1 $user@$ext 'exit' 2>&1 | grep 'timed out\|refused' | wc -l) = 0 ]; do echo -n "." ; sleep 5; done
done
echo "$GREEN" "ok" "$NORMAL"

#get ips
host_list=$(awk '{printf $1","}' hosts.txt|sed 's/,$//')
server=$(sed -n 1p hosts.txt|awk '{print $1}')
worker_list=$(sed 1d hosts.txt| awk '{printf $1","}'|sed 's/,$//')

#update DNS
echo -n " updating dns"
doctl compute domain records create $domain --record-type A --record-name $prefix --record-ttl 300 --record-data $server > /dev/null 2>&1
doctl compute domain records create $domain --record-type CNAME --record-name "*" --record-ttl 150 --record-data $prefix.$domain. > /dev/null 2>&1
echo "$GREEN" "ok" "$NORMAL"

#host modifications
if [[ "$image" = *"ubuntu"* ]]; then
  echo -n " adding os packages"
  pdsh -l $user -w $host_list 'mkdir -p /opt/kube; systemctl stop ufw; systemctl disable ufw; export DEBIAN_FRONTEND=noninteractive; apt update; #apt upgrade -y; apt autoremove -y' > /dev/null 2>&1
  echo "$GREEN" "ok" "$NORMAL"
fi

if [[ "$image" = *"centos"* || "$image" = *"rocky"* ]]; then
  echo -n " adding os packages"
  pdsh -l $user -w $host_list 'mkdir -p /opt/kube; yum install -y iscsi-initiator-utils; systemctl start iscsid.service; systemctl enable iscsid.service; yum update -y' > /dev/null 2>&1
  echo "$GREEN" "ok" "$NORMAL"
fi

#kernel tuning
echo -n " updating kernel settings"
pdsh -l $user -w $host_list 'cat << EOF >> /etc/sysctl.conf
# SWAP settings
vm.swappiness=0
vm.overcommit_memory=1

# Have a larger connection range available
net.ipv4.ip_local_port_range=1024 65000

# Increase max connection
net.core.somaxconn = 10000

# Reuse closed sockets faster
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15

# The maximum number of "backlogged sockets".  Default is 128.
net.core.somaxconn=4096
net.core.netdev_max_backlog=4096

# 16MB per socket - which sounds like a lot,
# but will virtually never consume that much.
net.core.rmem_max=16777216
net.core.wmem_max=16777216

# Various network tunables
net.ipv4.tcp_max_syn_backlog=20480
net.ipv4.tcp_max_tw_buckets=400000
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_syn_retries=2
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_wmem=4096 65536 16777216

# ARP cache settings for a highly loaded docker swarm
net.ipv4.neigh.default.gc_thresh1=8096
net.ipv4.neigh.default.gc_thresh2=12288
net.ipv4.neigh.default.gc_thresh3=16384

# ip_forward and tcp keepalive for iptables
net.ipv4.tcp_keepalive_time=600
net.ipv4.ip_forward=1

# monitor file system events
fs.inotify.max_user_instances=8192
fs.inotify.max_user_watches=1048576
EOF
sysctl -p' > /dev/null 2>&1
echo "$GREEN" "ok" "$NORMAL"

#or deploy k3s
if [ "$orchestrator" = no ]; then exit; fi

if [ "$orchestrator" = k3s ]; then
  echo -n " deploying k3s"
  k3sup install --ip $server --user $user --k3s-extra-args '--no-deploy traefik' --cluster --k3s-channel $k3s_channel --local-path ~/.kube/config > /dev/null 2>&1

  for workeri in $(awk '{print $1}' hosts.txt |sed 1d); do 
    k3sup join --ip $workeri --server-ip $server --user $user --k3s-extra-args '' --k3s-channel $k3s_channel > /dev/null 2>&1
  done 
  
  rsync -avP ~/.kube/config $user@$server:/opt/kube/config > /dev/null 2>&1
  
  echo "$GREEN" "ok" "$NORMAL"
fi

#or deploy rke
# https://docs.rke2.io/install/methods/#enterprise-linux-8
if [ "$orchestrator" = rke ]; then
  echo -n " deploying rke2 "
  ssh $user@$server 'mkdir -p /etc/rancher/rke2/ /var/lib/rancher/rke2/server/manifests/; echo -e "disable: rke2-ingress-nginx" > /etc/rancher/rke2/config.yaml; echo -e "---\napiVersion: helm.cattle.io/v1\nkind: HelmChartConfig\nmetadata:\n  name: rke2-ingress-nginx\n  namespace: kube-system\nspec:\n  valuesContent: |-\n    controller:\n      config:\n        use-forwarded-headers: true\n      extraArgs:\n        enable-ssl-passthrough: true" > /var/lib/rancher/rke2/server/manifests/rke2-ingress-nginx-config.yaml; curl -sfL https://get.rke2.io | INSTALL_RKE2_CHANNEL='$rke2_channel' RKE2_AGENT_TOKEN=rancherftw sh - && systemctl enable rke2-server.service && systemctl start rke2-server.service' > /dev/null 2>&1

  sleep 10

  token=$(ssh $user@$server 'cat /var/lib/rancher/rke2/server/node-token')

  pdsh -l $user -w $worker_list 'curl -sfL https://get.rke2.io | INSTALL_RKE2_CHANNEL='$rke2_channel' INSTALL_RKE2_TYPE=agent sh - && systemctl enable rke2-agent.service && mkdir -p /etc/rancher/rke2/ && echo "server: https://'$server':9345" > /etc/rancher/rke2/config.yaml && echo "token: '$token'" >> /etc/rancher/rke2/config.yaml && systemctl start rke2-agent.service' > /dev/null 2>&1

  rsync -avP $user@$server:/etc/rancher/rke2/rke2.yaml ~/.kube/config > /dev/null 2>&1
  sed -i'' -e "s/127.0.0.1/$server/g" ~/.kube/config 

  echo "$GREEN" "ok" "$NORMAL"
fi

echo -n " - cluster active "
sleep 5
until [ $(kubectl get node|grep NotReady|wc -l) = 0 ]; do echo -n "."; sleep 2; done
echo "$GREEN" "ok" "$NORMAL"
}

################################ rancher ##############################
function rancher () {
  echo " starting rancher server "
  echo -n " - helming "
  helm repo add rancher-latest https://releases.rancher.com/server-charts/latest > /dev/null 2>&1
  helm repo add jetstack https://charts.jetstack.io > /dev/null 2>&1
  helm repo update > /dev/null 2>&1

  kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.6.1/cert-manager.crds.yaml  > /dev/null 2>&1
  helm upgrade -i cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace --version v1.6.1  > /dev/null 2>&1
  helm upgrade -i rancher rancher-latest/rancher --create-namespace --namespace cattle-system --set hostname=rancher.$domain --set replicas=3 --set bootstrapPassword=bootStrapAllTheThings > /dev/null 2>&1
  echo "$GREEN" "ok" "$NORMAL"

  #traefik
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/rancher_traefik.yml  > /dev/null 2>&1

  # wait for rancher
  echo -n " - waiting for rancher "
  until [ $(curl -sk https://rancher.dockr.life/v3-public/authtokens | grep uuid | wc -l) = 1 ]; do 
    sleep 2
    echo -n "." 
    done
  token=$(curl -sk -X POST https://rancher.$domain/v3-public/localProviders/local?action=login -H 'content-type: application/json' -d '{"username":"admin","password":"bootStrapAllTheThings"}' | jq -r .token)
  echo "$GREEN" "ok" "$NORMAL"

  echo -n " - bootstrapping "
cat <<EOF | kubectl apply -f -  > /dev/null 2>&1
apiVersion: management.cattle.io/v3
kind: Setting
metadata:
  name: password-min-length
  namespace: cattle-system
value: "8"
EOF

  #set password
  curl -sk https://rancher.$domain/v3/users?action=changepassword -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"currentPassword":"bootStrapAllTheThings","newPassword":"'$password'"}'  > /dev/null 2>&1 

  api_token=$(curl -sk https://rancher.$domain/v3/token -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"type":"token","description":"automation"}' | jq -r .token)

  curl -sk https://rancher.$domain/v3/settings/server-url -H 'content-type: application/json' -H "Authorization: Bearer $api_token" -X PUT -d '{"name":"server-url","value":"https://'$server'"}'  > /dev/null 2>&1

  curl -sk https://rancher.$domain/v3/settings/telemetry-opt -X PUT -H 'content-type: application/json' -H 'accept: application/json' -H "Authorization: Bearer $api_token" -d '{"value":"out"}' > /dev/null 2>&1
  echo "$GREEN" "ok" "$NORMAL"
}

################################ longhorn ##############################
function longhorn () {
  echo -n  " - longhorn "
  kubectl apply -f https://raw.githubusercontent.com/longhorn/longhorn/master/deploy/longhorn.yaml > /dev/null 2>&1

  sleep 5

  #wait for longhorn to initiaize
  until [ $(kubectl get pod -n longhorn-system | grep -v 'Running\|NAME' | wc -l) = 0 ] && [ "$(kubectl get pod -n longhorn-system | wc -l)" -gt 20 ] ; do echo -n "." ; sleep 2; done
  # testing out ` kubectl wait --for condition=containersready -n longhorn-system pod --all`

  kubectl patch storageclass longhorn -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}' > /dev/null 2>&1
  if [ "$orchestrator" = k3s ]; then kubectl patch storageclass local-path -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"false"}}}' > /dev/null 2>&1; fi

  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/traefik_longhorn.yml > /dev/null 2>&1

  echo "$GREEN" "ok" "$NORMAL"
}

################################ traefik ##############################
function traefik () {
  echo -n  " - traefik "
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/traefik_crd_deployment.yml > /dev/null 2>&1
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/traefik_ingressroute.yaml > /dev/null 2>&1
  if [ "$orchestrator" = rke ]; then 
    kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/traefik_rke.yml > /dev/null 2>&1
  fi
  echo "$GREEN" "ok" "$NORMAL"
}

################################ neu ##############################
function neu () {
  echo -n  "  - neuvector "
  helm repo update > /dev/null 2>&1
  kubectl create namespace neuvector > /dev/null 2>&1
  kubectl create serviceaccount neuvector -n neuvector > /dev/null 2>&1
  kubectl apply -f ~/Dropbox/work/neuvector/neu_traefik.yaml > /dev/null 2>&1
  helm install neuvector --namespace neuvector neuvector/core  --set imagePullSecrets=regsecret -f ~/Dropbox/work/neuvector/neu_values.yml > /dev/null 2>&1

  until [[ "$(curl -skL -H "Content-Type: application/json" -o /dev/null -w '%{http_code}' https://neuvector.$domain/auth -d '{"username": "admin", "password": "admin"}')" == "200" ]]; do echo -n .; sleep 1; done

  TOKEN=$(curl -sk -H "Content-Type: application/json" https://neuvector.$domain/auth -d '{"username": "admin", "password": "admin"}' | jq  -r .token.token)

  curl -sk -H "Content-Type: application/json" -H 'Token: '$TOKEN https://neuvector.$domain/eula -d '{"accepted":true}' > /dev/null 2>&1

  curl -sk -H "Content-Type: application/json" -H 'Token: '$TOKEN -X PATCH https://neuvector.$domain/user -d '{"domain_permissions":{},"server":"","email":"","role":"admin","username":"admin","default_password":true,"password_days_until_expire":-1,"global_permissions":[{"id":"config","read":true,"write":true},{"id":"nv_resource","read":true,"write":true},{"id":"rt_scan","read":true,"write":true},{"id":"reg_scan","read":true,"write":true},{"id":"ci_scan","read":false,"write":true},{"id":"cloud","read":true,"write":true},{"id":"rt_policy","read":true,"write":true},{"id":"admctrl","read":true,"write":true},{"id":"compliance","read":true,"write":true},{"id":"audit_events","read":true,"write":false},{"id":"security_events","read":true,"write":false},{"id":"events","read":true,"write":false},{"id":"authentication","read":true,"write":true},{"id":"authorization","read":true,"write":true},{"id":"vulnerability","read":true,"write":true}],"locale":"en","fullname":"admin","token":"'$TOKEN'","timeout":300,"modify_password":false,"password":"admin","new_password":"'$password'"}' > /dev/null 2>&1

  TOKEN=$(curl -sk -H "Content-Type: application/json" https://neuvector.$domain/auth -d '{"username": "admin", "password": "'$password'"}' | jq  -r .token.token)

  curl -sk -X POST -H "Content-Type: application/json" -H 'Accept: application/json, text/plain, */*' -H 'Token: '$TOKEN https://neuvector.$domain/license/update -d '{"license_key":"'$(cat neuvector.lic)'"}' --compressed > /dev/null 2>&1

  echo "$GREEN" "ok" "$NORMAL"
}

################################ rox ##############################
function rox () {
# ensure no central-bundle is not present
  if [ -d central-bundle ]; then
    echo "$RED" "Warning - cental-bundle already detected..." "$NORMAL"
    exit
  fi

# check for credentials for help.stackrox.com 
  if [ "$REGISTRY_USERNAME" = "" ] || [ "$REGISTRY_PASSWORD" = "" ]; then echo "Please setup a ENVs for REGISTRY_USERNAME and REGISTRY_PASSWORD..."; exit; fi

# get latest roxctl
# for MacOS you may need to remove the quarentine for it
# xattr -d com.apple.quarantine /usr/local/bin/roxctl
  echo -n " getting latest roxctl "
    curl -#L https://mirror.openshift.com/pub/rhacs/assets/$version/bin/$roxOS/roxctl -o /usr/local/bin/roxctl > /dev/null 2>&1
    chmod 755 /usr/local/bin/roxctl
  echo "$GREEN" "ok" "$NORMAL"

  echo " deploying :"
# deploy traefik
  traefik

# deploy longhorn
  longhorn

  echo -n  "  - stackrox "  
# generate stackrox yaml
  roxctl central generate k8s pvc --main-image registry.redhat.io/rh-acs/main:3.67.2 --scanner-db-image registry.redhat.io/rh-acs/scanner-db:2.21.0 --scanner-image registry.redhat.io/rh-acs/scanner:2.21.0 --storage-class longhorn --size 30 --enable-telemetry=false --lb-type np --password $password > /dev/null 2>&1

# setup and install central
  ./central-bundle/central/scripts/setup.sh > /dev/null 2>&1
  kubectl apply -R -f central-bundle/central > /dev/null 2>&1

 # get the server and port from kubectl - assuming nodeport
  server=$(kubectl get nodes -o json | jq -r '.items[0].status.addresses[] | select( .type=="InternalIP" ) | .address ')
  rox_port=$(kubectl -n stackrox get svc central-loadbalancer |grep Node|awk '{print $5}'|sed -e 's/443://g' -e 's#/TCP##g')
  
# wait for central to be up
  until [ $(curl -kIs --max-time 5 --connect-timeout 5 https://$server:$rox_port|head -n1|wc -l) = 1 ]; do echo -n "." ; sleep 2; done
  
# setup and install scanner
  ./central-bundle/scanner/scripts/setup.sh > /dev/null 2>&1
  kubectl apply -R -f central-bundle/scanner/ > /dev/null 2>&1

# ask central for a sensor bundle
  roxctl sensor generate k8s -e $server:$rox_port --name k3s --central central.stackrox:443 --insecure-skip-tls-verify --collection-method ebpf --admission-controller-listen-on-updates --admission-controller-listen-on-creates --main-image-repository registry.redhat.io/rh-acs/main --collector-image-repository registry.redhat.io/rh-acs/collector -p $password > /dev/null 2>&1

# install sensors
  ./sensor-k3s/sensor.sh > /dev/null 2>&1

# deploy traefik CRD IngressRoute
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/stackrox_traefik_crd.yml > /dev/null 2>&1

  echo "$GREEN" "ok" "$NORMAL"

  echo -n "  - creating api token "
  sleep 5
  curl -sk -X POST -u admin:$password https://stackrox.$domain/v1/apitokens/generate -d '{"name":"admin","role":null,"roles":["Admin"]}'| jq -r .token > ROX_API_TOKEN
  echo "$GREEN""ok" "$NORMAL"
}

############################# demo ################################
function demo () {
  command -v linkerd >/dev/null 2>&1 || { echo "$RED" " ** Linkerd was not found. Please install ** " "$NORMAL" >&2; exit 1; }

  echo -n "  - graylog ";kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/graylog.yaml > /dev/null 2>&1; echo "$GREEN""ok" "$NORMAL"

  echo -n "  - whoami ";kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/whoami.yml > /dev/null 2>&1; echo "$GREEN""ok" "$NORMAL"

  echo -n "  - flask ";kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/flask.yml > /dev/null 2>&1; echo "$GREEN""ok" "$NORMAL"
  
  echo -n "  - jenkins "; kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/jenkins_containerd.yml > /dev/null 2>&1
   # curl -sk -X POST -u admin:$password https://stackrox.$domain/v1/apitokens/generate -d '{"name":"jenkins","role":null,"roles":["Continuous Integration"]}'| jq -r .token > jenkins_TOKEN
  echo "$GREEN""ok" "$NORMAL"

  echo -n "  - linkerd "; 
  #linkerd install | sed "s/localhost|/linkerd.$domain|localhost|/g" | kubectl apply -f - > /dev/null 2>&1
  #kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/linkerd_traefik.yml > /dev/null 2>&1
  echo "$GREEN""ok" "$NORMAL"

  echo -n "  - prometheus/grafana "
  #kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/prometheus/prometheus.yml > /dev/null 2>&1
  #kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/prometheus/kube-state-metrics-complete.yml > /dev/null 2>&1
  #kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/prometheus/prometheus_grafana_dashboards.yml > /dev/null 2>&1
  echo "$GREEN""ok" "$NORMAL"

  echo -n "  - openfaas "
  #kubectl apply -f https://raw.githubusercontent.com/openfaas/faas-netes/master/namespaces.yml > /dev/null 2>&1
  #kubectl -n openfaas create secret generic basic-auth --from-literal=basic-auth-user=admin --from-literal=basic-auth-password="$password" > /dev/null 2>&1
  #kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/openfass.yml > /dev/null 2>&1
  #kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/openfaas_traefik.yml  > /dev/null 2>&1
  echo "$GREEN""ok" "$NORMAL"

  echo -n "  - harbor "
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/harbor_traefik_ingress.yml > /dev/null 2>&1
  echo "$GREEN""ok" "$NORMAL"
  
  echo -n "  - keycloak "
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/keycloak.yml > /dev/null 2>&1
  echo "$GREEN""ok" "$NORMAL"

  echo -n "  - code-server "
  rsync -avP ~/.kube/config $user@$server:/opt/kube/config > /dev/null 2>&1
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/code-server.yml > /dev/null 2>&1
  echo "$GREEN""ok" "$NORMAL"
} 

################################ keycloak ##############################
function keycloak () {
  echo -n "  - keycloak ";kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/keycloak.yml > /dev/null 2>&1; echo "$GREEN""ok" "$NORMAL"
  echo -n "    - configuring all the things"

  until [ $(kubectl get pod -n keycloak | grep -v 'Running\|NAME\|svclb' | wc -l) = 0 ] ; do echo -n "." ; sleep 2; done

  sleep 30
  
  export KEY_URL=keycloak.dockr.life
  export ROX_URL=stackrox.dockr.life

  # get auth token - notice keycloak's password 
  export key_token=$(curl -sk -X POST https://$KEY_URL/auth/realms/master/protocol/openid-connect/token -d 'client_id=admin-cli&username=admin&password='$password'&credentialId=&grant_type=password' | jq -r .access_token)

  # add realm
  curl -sk -X POST https://$KEY_URL/auth/admin/realms -H "authorization: Bearer $key_token" -H 'accept: application/json, text/plain, */*' -H 'content-type: application/json;charset=UTF-8' -d '{"enabled":true,"id":"stackrox","realm":"stackrox"}'

  # add client
  curl -sk -X POST https://$KEY_URL/auth/admin/realms/stackrox/clients -H "authorization: Bearer $key_token" -H 'accept: application/json, text/plain, */*' -H 'content-type: application/json;charset=UTF-8' -d '{"enabled":true,"attributes":{},"redirectUris":[],"clientId":"stackrox","protocol":"openid-connect","publicClient": false,"redirectUris":["https://'$ROX_URL'/sso/providers/oidc/callback"]}'
  #,"implicitFlowEnabled":true

  # get client id
  export client_id=$(curl -sk  https://$KEY_URL/auth/admin/realms/stackrox/clients/ -H "authorization: Bearer $key_token"  | jq -r '.[] | select(.clientId=="stackrox") | .id')

  # get client_secret
  export client_secret=$(curl -sk  https://$KEY_URL/auth/admin/realms/stackrox/clients/$client_id/client-secret -H "authorization: Bearer $key_token" | jq -r .value)

  # add keycloak user clemenko / Pa22word
  curl -k 'https://keycloak.dockr.life/auth/admin/realms/stackrox/users' -H 'Content-Type: application/json' -H "authorization: Bearer $key_token" -d '{"enabled":true,"attributes":{},"groups":[],"credentials":[{"type":"password","value":"Pa22word","temporary":false}],"username":"clemenko","emailVerified":"","firstName":"Andy","lastName":"Clemenko"}' 

  # config stackrox
  export auth_id=$(curl -sk -X POST -u admin:$password https://$ROX_URL/v1/authProviders -d '{"type":"oidc","uiEndpoint":"'$ROX_URL'","enabled":true,"config":{"mode":"query","do_not_use_client_secret":"false","client_secret":"'$client_secret'","issuer":"https+insecure://'$KEY_URL'/auth/realms/stackrox","client_id":"stackrox"},"name":"stackrox"}' | jq -r .id)

  # change default to Analyst
  curl -sk -X POST -u admin:$password https://$ROX_URL/v1/groups -d '{"props":{"authProviderId":"'$auth_id'"},"roleName":"Analyst"}'

  echo "$GREEN""ok" "$NORMAL"
}


############################# slides ################################
function slides () {
  echo -n "  - adding slides "
  rsync -avP /Users/clemenko/Dropbox/work/talks/markdown/* $user@$server:/opt/slides > /dev/null 2>&1
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/slides.yml > /dev/null 2>&1
  echo "$GREEN""ok" "$NORMAL"
}


############################## kill ################################
#remove the vms
function kill () {

if [ -f hosts.txt ]; then
  echo -n " killing it all "
  for i in $(awk '{print $2}' hosts.txt); do doctl compute droplet delete --force $i; done
  for i in $(awk '{print $1}' hosts.txt); do ssh-keygen -q -R $i > /dev/null 2>&1; done
  for i in $(doctl compute domain records list dockr.life|grep 'k3s\|k3s'|awk '{print $1}'); do doctl compute domain records delete -f dockr.life $i; done

  rm -rf *.txt *.log *.zip *.pem *.pub env.* backup.tar ~/.kube/config central* sensor* *token kubeconfig *TOKEN 

else
  echo -n " no hosts file found "
fi

echo "$GREEN" "ok" "$NORMAL"
}

############################# usage ################################
function usage () {
  echo ""
  echo "-------------------------------------------------"
  echo ""
  echo " Usage: $0 {up|kill|rox|demo|full}"
  echo ""
  echo " ./k3s.sh up # build the vms "
  echo " ./k3s.sh simple # simple deployment"
  echo " ./k3s.sh kill # kill the vms"
  echo " ./k3s.sh demo # deploy demo apps"
  echo " ./k3s.sh full # full send"
  echo ""
  echo "-------------------------------------------------"
  echo ""
  exit 1
}

case "$1" in
        up) up;;
        simple) up && traefik && longhorn;;
        kill) kill;;
        rox) rox;;
        neu) neu;;
        traefik) traefik;;
        longhorn) longhorn;;
        rancher) rancher;;
        demo) demo;;
        slides) slides;;
        full) simple && demo && slides;;
        *) usage;;
esac
