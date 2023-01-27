#!/usr/bin/env bash

# https://github.com/clemenko/k3s/blob/master/k3s.sh
# this script assumes digitalocean is setup with DNS.
# you need doctl, kubectl, uuid, jq, k3sup, pdsh and curl installed.
# clemenko@gmail.com 

###################################
# edit varsw
###################################
set -e
num=3
password=Pa22word
zone=nyc1
size=s-4vcpu-8gb
key=30:98:4f:c5:47:c2:88:28:fe:3c:23:cd:52:49:51:01
domain=rfed.site

#image=ubuntu-22-04-x64
image=rockylinux-9-x64

# rancher / k8s
prefix=rke- # no rke k3s
k3s_channel=stable # latest
rke2_channel=v1.24 #latest

# ingress nginx or traefik
ingress=traefik # traefik

# stackrox automation
export REGISTRY_USERNAME=AndyClemenko
export rox_version=3.72.1

######  NO MOAR EDITS #######
export RED='\x1b[0;31m'
export GREEN='\x1b[32m'
export BLUE='\x1b[34m'
export YELLOW='\x1b[33m'
export NO_COLOR='\x1b[0m'
export PDSH_RCMD_TYPE=ssh

#better error checking
command -v doctl >/dev/null 2>&1 || { echo -e "$RED" " ** Doctl was not found. Please install. ** " "$NO_COLOR" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo -e "$RED" " ** Curl was not found. Please install. ** " "$NO_COLOR" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo -e "$RED" " ** Jq was not found. Please install. ** " "$NO_COLOR" >&2; exit 1; }
command -v pdsh >/dev/null 2>&1 || { echo -e "$RED" " ** Pdsh was not found. Please install. ** " "$NO_COLOR" >&2; exit 1; }
command -v k3sup >/dev/null 2>&1 || { echo -e "$RED" " ** K3sup was not found. Please install. ** " "$NO_COLOR" >&2; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo -e "$RED" " ** Kubectl was not found. Please install. ** " "$NO_COLOR" >&2; exit 1; }

#### doctl_list ####
function dolist () { harvester vm |grep -v NAME | grep Run | grep $prefix| awk '{print $1"  "$2"  "$6"  "$4"  "$5}'; }

server=$(dolist | sed -n 1p | awk '{print $3}')

################################# up ################################
function up () {
build_list=""
# helm repo update > /dev/null 2>&1

if [ ! -z $(dolist) ]; then
  echo -e "$RED" "Warning - cluster already detected..." "$NO_COLOR"
  exit
fi

#rando list generation
for i in $(seq 1 $num); do build_list="$build_list $prefix$i"; done

#build VMS
echo -e -n " building vms -$build_list "
harvester vm create --template rocky9 --count $num rke > /dev/null 2>&1
until [ $(dolist | grep "192.168" | wc -l) = $num ]; do echo -e -n "." ; sleep 2; done

echo -e "$GREEN" "ok" "$NO_COLOR"

#check for SSH
echo -e -n " checking for ssh "
for ext in $(dolist | awk '{print $3}'); do
  until [ $(ssh -o ConnectTimeout=1 root@$ext 'exit' 2>&1 | grep 'timed out\|refused' | wc -l) = 0 ]; do echo -e -n "." ; sleep 5; done
done
echo -e "$GREEN" "ok" "$NO_COLOR"

#get ips
host_list=$(dolist | awk '{printf $3","}' | sed 's/,$//')
server=$(dolist | sed -n 1p | awk '{print $3}')
worker_list=$(dolist | sed 1d | awk '{printf $3","}' | sed 's/,$//')

#update DNS
echo -e -n " updating dns"
doctl compute domain records create $domain --record-type A --record-name $prefix"1" --record-ttl 300 --record-data $server > /dev/null 2>&1
doctl compute domain records create $domain --record-type CNAME --record-name "*" --record-ttl 150 --record-data $prefix"1".$domain. > /dev/null 2>&1
echo -e "$GREEN" "ok" "$NO_COLOR"

sleep 10

#host modifications
if [[ "$image" = *"ubuntu"* ]]; then
  echo -e -n " adding os packages"
  pdsh -l root -w $host_list 'mkdir -p /opt/kube; systemctl stop ufw; systemctl disable ufw; echo -e "PubkeyAcceptedKeyTypes=+ssh-rsa" >> /etc/ssh/sshd_config; systemctl restart sshd; export DEBIAN_FRONTEND=noninteractive; apt update; apt install nfs-common -y;  #apt upgrade -y; apt autoremove -y' > /dev/null 2>&1
  echo -e "$GREEN" "ok" "$NO_COLOR"
fi

if [[ "$image" = *"centos"* || "$image" = *"rocky"* ]]; then
  echo -e -n " adding os packages"
  pdsh -l root -w $host_list 'echo -e "[keyfile]\nunmanaged-devices=interface-name:cali*;interface-name:flannel*" > /etc/NetworkManager/conf.d/rke2-canal.conf; mkdir -p /opt/kube; yum install -y nfs-utils cryptsetup iscsi-initiator-utils; systemctl enable iscsid; systemctl start iscsid; yum update -y selinux*; #yum update -y' > /dev/null 2>&1
  echo -e "$GREEN" "ok" "$NO_COLOR"
fi

#kernel tuning
echo -e -n " updating kernel settings"
pdsh -l root -w $host_list 'cat << EOF >> /etc/sysctl.conf
# SWAP settings
vm.swappiness=0
vm.panic_on_oom=0
vm.overcommit_memory=1
kernel.panic=10
kernel.panic_on_oops=1
vm.max_map_count = 262144

# Have a larger connection range available
net.ipv4.ip_local_port_range=1024 65000

# Increase max connection
net.core.somaxconn=10000

# Reuse closed sockets faster
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15

# The maximum number of "backlogged sockets".  Default is 128.
net.core.somaxconn=4096
net.core.netdev_max_backlog=4096

# 16MB per socket - which sounds like a lot,
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
echo -e "$GREEN" "ok" "$NO_COLOR"

#or deploy k3s
if [ "$prefix" != k3s ] && [ "$prefix" != rke- ]; then exit; fi

if [ "$prefix" = k3s ]; then
  echo -e -n " deploying k3s"
  k3sup install --ip $server --user root --k3s-extra-args '--no-deploy traefik' --cluster --k3s-channel $k3s_channel --local-path ~/.kube/config > /dev/null 2>&1

  for workeri in $(dolist | sed 1d | awk '{print $3}'); do 
    k3sup join --ip $workeri --server-ip $server --user root --k3s-extra-args '' --k3s-channel $k3s_channel > /dev/null 2>&1
  done 
  
  rsync -avP ~/.kube/config root@$server:/opt/kube/config > /dev/null 2>&1
  
  echo -e "$GREEN" "ok" "$NO_COLOR"
fi

#or deploy rke2
# https://docs.rke2.io/install/methods/#enterprise-linux-8
if [ "$prefix" = rke- ]; then
  echo -e -n " deploying rke2 "
  if [ "$ingress" = nginx ]; then ingress_file="#disable: rke2-ingress-nginx"; else ingress_file="disable: rke2-ingress-nginx"; fi

  ssh root@$server 'mkdir -p /etc/rancher/rke2/ /var/lib/rancher/rke2/server/manifests/; useradd -r -c "etcd user" -s /sbin/nologin -M etcd -U; echo -e "apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n- level: RequestResponse" > /etc/rancher/rke2/audit-policy.yaml; echo -e "'$ingress_file'\n#profile: cis-1.6\nselinux: true\nsecrets-encryption: true\ntls-san:\n- rke."'$domain'"\nnwrite-kubeconfig-mode: 0600\nkube-controller-manager-arg:\n- bind-address=127.0.0.1\n- use-service-account-credentials=true\n- tls-min-version=VersionTLS12\n- tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\nkube-scheduler-arg:\n- tls-min-version=VersionTLS12\n- tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\nkube-apiserver-arg:\n- tls-min-version=VersionTLS12\n- tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\n- authorization-mode=RBAC,Node\n- anonymous-auth=false\n- audit-policy-file=/etc/rancher/rke2/audit-policy.yaml\n- audit-log-mode=blocking-strict\n- audit-log-maxage=30\nkubelet-arg:\n- protect-kernel-defaults=true\n- read-only-port=0\n- authorization-mode=Webhook" > /etc/rancher/rke2/config.yaml ; echo -e "---\napiVersion: helm.cattle.io/v1\nkind: HelmChartConfig\nmetadata:\n  name: rke2-ingress-nginx\n  namespace: kube-system\nspec:\n  valuesContent: |-\n    controller:\n      config:\n        use-forwarded-headers: true\n      extraArgs:\n        enable-ssl-passthrough: true" > /var/lib/rancher/rke2/server/manifests/rke2-ingress-nginx-config.yaml; curl -sfL https://get.rke2.io | INSTALL_RKE2_CHANNEL='$rke2_channel' sh - && systemctl enable --nw  rke2-server.service' > /dev/null 2>&1

# for CIS
#  cp -f /usr/local/share/rke2/rke2-cis-sysctl.conf /etc/sysctl.d/60-rke2-cis.conf; systemctl restart systemd-sysctl;

  sleep 10

  token=$(ssh root@$server 'cat /var/lib/rancher/rke2/server/node-token')

  pdsh -l root -w $worker_list 'curl -sfL https://get.rke2.io | INSTALL_RKE2_CHANNEL='$rke2_channel' INSTALL_RKE2_TYPE=agent sh - && systemctl enable rke2-agent.service && mkdir -p /etc/rancher/rke2/ && echo -e "server: https://"'$server'":9345\ntoken: "'$token'"\nwrite-kubeconfig-mode: 0600\n#profile: cis-1.6\nkube-apiserver-arg:\n- authorization-mode=RBAC,Node\nkubelet-arg:\n- protect-kernel-defaults=true\n- read-only-port=0\n- authorization-mode=Webhook" > /etc/rancher/rke2/config.yaml && systemctl enable --now rke2-agent.service' > /dev/null 2>&1

  rsync -avP root@$server:/etc/rancher/rke2/rke2.yaml ~/.kube/config > /dev/null 2>&1
  chmod 0600 ~/.kube/config
  sed -i'' -e "s/127.0.0.1/$server/g" ~/.kube/config 

  echo -e "$GREEN" "ok" "$NO_COLOR"
fi

echo -e -n " - cluster active "
sleep 5
until [ $(kubectl get node|grep NotReady|wc -l) = 0 ]; do echo -e -n "."; sleep 2; done
echo -e "$GREEN" "ok" "$NO_COLOR"
}

################################ rancher ##############################
function rancher () {

  if [ -z $(dolist | awk '{printf $3","}' | sed 's/,$//') ]; then
    echo -e "$BLUE" "Building cluster first." "$NO_COLOR"
    up && traefik && longhorn
  fi

  echo -e " deploying rancher"

  echo -e -n " - helming "
  helm repo add rancher-latest https://releases.rancher.com/server-charts/latest > /dev/null 2>&1
  helm repo add prometheus-community https://prometheus-community.github.io/helm-charts > /dev/null 2>&1
  helm repo add jetstack https://charts.jetstack.io > /dev/null 2>&1

  helm upgrade -i cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace --set installCRDs=true > /dev/null 2>&1 #--version v1.6.1

  # custom TLS certs
  # kubectl create ns cattle-system 
  # kubectl -n cattle-system create secret tls tls-rancher-ingress --cert=tls.crt --key=tls.key
  # kubectl -n cattle-system create secret generic tls-ca --from-file=cacerts.pem
  # kubectl -n cattle-system create secret generic tls-ca-additional --from-file=ca-additional.pem=cacerts.pem

  # helm upgrade -i rancher rancher-latest/rancher --namespace cattle-system --set hostname=rancher.$domain --set bootstrapPassword=bootStrapAllTheThings --set replicas=1 --set additionalTrustedCAs=true --set ingress.tls.source=secret --set ingress.tls.secretName=tls-rancher-ingress --set privateCA=true
 
  helm upgrade -i rancher rancher-latest/rancher --namespace cattle-system --create-namespace --set hostname=rancher.$domain --set bootstrapPassword=bootStrapAllTheThings --set replicas=1 --set auditLog.level=2 --set auditLog.destination=hostPath > /dev/null 2>&1
  # --version 2.6.4-rc4 --devel

  echo -e "$GREEN" "ok" "$NO_COLOR"

  #traefik
  if [ "$ingress" = traefik ]; then curl -s https://raw.githubusercontent.com/clemenko/k8s_yaml/master/rancher_traefik.yml | sed "s/rfed.io/$domain/g" | kubectl apply -f - > /dev/null 2>&1; fi 

  # wait for rancher
  echo -e -n " - waiting for rancher "
  until [ $(curl -sk https://rancher.$domain/v3-public/authtokens | grep uuid | wc -l) = 1 ]; do 
    sleep 2
    echo -e -n "." 
    done
  token=$(curl -sk -X POST https://rancher.$domain/v3-public/localProviders/local?action=login -H 'content-type: application/json' -d '{"username":"admin","password":"bootStrapAllTheThings"}' | jq -r .token)
  echo -e "$GREEN" "ok" "$NO_COLOR"

  echo -e -n " - bootstrapping "
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

  curl -sk https://rancher.$domain/v3/settings/server-url -H 'content-type: application/json' -H "Authorization: Bearer $api_token" -X PUT -d '{"name":"server-url","value":"https://rancher.'$domain'"}'  > /dev/null 2>&1

  curl -sk https://rancher.$domain/v3/settings/telemetry-opt -X PUT -H 'content-type: application/json' -H 'accept: application/json' -H "Authorization: Bearer $api_token" -d '{"value":"out"}' > /dev/null 2>&1
  echo -e "$GREEN" "ok" "$NO_COLOR"

  #fix for local cluster fleet
  kubectl patch ClusterGroup -n fleet-local default --type=json -p='[{"op": "remove", "path": "/spec/selector/matchLabels/name"}]' > /dev/null 2>&1

}

################################ longhorn ##############################
function longhorn () {
  echo -e -n  " - longhorn "
#  kubectl apply -f https://raw.githubusercontent.com/longhorn/longhorn/v1.3.2/deploy/longhorn.yaml > /dev/null 2>&1

#  helm repo add longhorn https://charts.longhorn.io && helm repo update
  helm upgrade -i longhorn longhorn/longhorn --namespace longhorn-system --create-namespace --set ingress.enabled=true --set ingress.host=longhorn.$domain > /dev/null 2>&1

  sleep 5

  #wait for longhorn to initiaize
  until [ $(kubectl get pod -n longhorn-system | grep -v 'Running\|NAME' | wc -l) = 0 ] && [ "$(kubectl get pod -n longhorn-system | wc -l)" -gt 20 ] ; do echo -e -n "." ; sleep 2; done
  # testing out ` kubectl wait --for condition=containersready -n longhorn-system pod --all`

  kubectl patch storageclass longhorn -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}' > /dev/null 2>&1
  if [ "$prefix" = k3s ]; then kubectl patch storageclass local-path -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"false"}}}' > /dev/null 2>&1; fi

  # if [ "$ingress" = traefik ]; then kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/traefik_longhorn.yml > /dev/null 2>&1; fi;

  # add encryption per volume storage class 
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/longhorn_encryption.yml > /dev/null 2>&1

  echo -e "$GREEN" "ok" "$NO_COLOR"
}

################################ traefik ##############################
function traefik () {
  echo -e -n  " - traefik "
  #helm repo add traefik https://helm.traefik.io/traefik

  if [ "$ingress" = traefik ]; then
    if [ "$prefix" = rke- ]; then 

        kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/traefik_rke.yml > /dev/null 2>&1
        # helm upgrade -i traefik traefik/traefik --namespace traefik --create-namespace --set service.type=NodePort --set deployment.kind=DaemonSet --set ports.web.port=80 --set ports.websecure.port=443 --set hostNetwork=true --set securityContext.runAsNonRoot=false --set securityContext.capabilities.add[0]=NET_BIND_SERVICE --set securityContext.allowPrivilegeEscalation=true --set securityContext.runAsGroup=0 --set securityContext.runAsUser=0
    elif [ "$prefix" = k3s ]; then
        kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/traefik_crd_deployment.yml > /dev/null 2>&1
        # helm upgrade -i traefik traefik/traefik --namespace traefik --create-namespace --set service.type=NodePort --set deployment.kind=DaemonSet --set ports.web.port=80 --set ports.websecure.port=443 --set hostNetwork=true --set securityContext.runAsNonRoot=false --set securityContext.capabilities.add[0]=NET_BIND_SERVICE --set securityContext.allowPrivilegeEscalation=true --set securityContext.runAsGroup=0 --set securityContext.runAsUser=0
    fi
    curl -s https://raw.githubusercontent.com/clemenko/k8s_yaml/master/traefik_ingressroute.yaml | sed "s/rfed.io/$domain/g" | kubectl apply -f -   > /dev/null 2>&1
    #kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/traefik_ingressroute.yaml > /dev/null 2>&1
    echo -e "$GREEN" "ok" "$NO_COLOR"
  else 
   echo -e "$RED" "nginx installed" "$NO_COLOR"
  fi
}

################################ neu ##############################
function neu () {
  echo -e -n  " - neuvector "

  # helm repo add neuvector https://neuvector.github.io/neuvector-helm/
  export CAROOT=certs/
  mkdir -p certs/
  mkcert -client -cert-file certs/cert.pem -key-file certs/cert.key NeuVector neuvector.nv.local > /dev/null 2>&1
  mv certs/rootCA.pem certs/ca.cert

  kubectl create ns neuvector > /dev/null 2>&1
  kubectl create secret generic internal-cert -n neuvector --from-file=certs/cert.key --from-file=certs/cert.pem --from-file=certs/ca.cert > /dev/null 2>&1

  helm upgrade -i neuvector -n neuvector neuvector/core --create-namespace  --set imagePullSecrets=regsecret --set k3s.enabled=true --set k3s.runtimePath=/run/k3s/containerd/containerd.sock --set manager.ingress.enabled=true --set manager.ingress.host=neuvector.$domain --set manager.svc.type=ClusterIP --set controller.pvc.enabled=true --set controller.pvc.capacity=500Mi --set controller.internal.certificate.secret=internal-cert --set cve.scanner.internal.certificate.secret=internal-cert --set enforcer.internal.certificate.secret=internal-cert > /dev/null 2>&1

  curl -s https://raw.githubusercontent.com/clemenko/k8s_yaml/master/neuvector_traefik.yml | sed "s/rfed.io/$domain/g" | kubectl apply -f - > /dev/null 2>&1

  until [[ "$(curl -skL -H "Content-Type: application/json" -o /dev/null -w '%{http_code}' https://neuvector.$domain/auth -d '{"username": "admin", "password": "admin"}')" == "200" ]]; do echo -e -n .; sleep 2; done

  TOKEN=$(curl -sk -H "Content-Type: application/json" https://neuvector.$domain/auth -d '{"username": "admin", "password": "admin"}' | jq  -r .token.token)

  curl -sk -H "Content-Type: application/json" -H 'Token: '$TOKEN https://neuvector.$domain/eula -d '{"accepted":true}' > /dev/null 2>&1

  curl -sk -H "Content-Type: application/json" -H 'Token: '$TOKEN -X PATCH https://neuvector.$domain/user -d '{"domain_permissions":{},"server":"","email":"","role":"admin","username":"admin","default_password":true,"password_days_until_expire":-1,"global_permissions":[{"id":"config","read":true,"write":true},{"id":"nv_resource","read":true,"write":true},{"id":"rt_scan","read":true,"write":true},{"id":"reg_scan","read":true,"write":true},{"id":"ci_scan","read":false,"write":true},{"id":"cloud","read":true,"write":true},{"id":"rt_policy","read":true,"write":true},{"id":"admctrl","read":true,"write":true},{"id":"compliance","read":true,"write":true},{"id":"audit_events","read":true,"write":false},{"id":"security_events","read":true,"write":false},{"id":"events","read":true,"write":false},{"id":"authentication","read":true,"write":true},{"id":"authorization","read":true,"write":true},{"id":"vulnerability","read":true,"write":true}],"locale":"en","fullname":"admin","token":"'$TOKEN'","timeout":300,"modify_password":false,"password":"admin","new_password":"'$password'"}' > /dev/null 2>&1

  #TOKEN=$(curl -sk -H "Content-Type: application/json" https://neuvector.$domain/auth -d '{"username": "admin", "password": "'$password'"}' | jq  -r .token.token)

  # add license
  #curl -sk -X POST -H "Content-Type: application/json" -H 'Accept: application/json, text/plain, */*' -H 'Token: '$TOKEN https://neuvector.$domain/license/update -d '{"license_key":"'$(cat neuvector.lic)'"}' --compressed > /dev/null 2>&1

  echo -e "$GREEN" "ok" "$NO_COLOR"
}

################################ rox ##############################
function rox () {
# helm repo add rhacs https://mirror.openshift.com/pub/rhacs/charts/
# helm repo update

  echo -e " deploying :"
  echo -e -n  "  - stackrox - central "  
  helm upgrade -i -n stackrox --create-namespace stackrox-central-services rhacs/central-services --set imagePullSecrets.username=AndyClemenko --set imagePullSecrets.password=$REGISTRY_PASSWORD --set central.exposure.loadBalancer.enabled=true --set central.disableTelemetry=true --set central.persistence.persistentVolumeClaim.size=5Gi --set central.adminPassword.value=Pa22word > /dev/null 2>&1

  curl -s kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/stackrox_traefik_crd.yml | sed "s/rfed.io/$domain/g" | kubectl apply -f - > /dev/null 2>&1
  
 # wait for central to be up
  until [ $(curl -ks --max-time 5 --connect-timeout 5 https://stackrox.$domain/main/system-health|grep JavaScript|wc -l) = 1 ]; do echo -e -n "." ; sleep 2; done
  sleep 5
  echo -e "$GREEN" "ok" "$NO_COLOR"

  echo -e -n "  - creating api token "
  export ROX_API_TOKEN=$(curl -sk -X POST -u admin:$password https://stackrox.$domain/v1/apitokens/generate -d '{"name":"admin","role":null,"roles":["Admin"]}'| jq -r .token)
  echo -e "$GREEN""ok" "$NO_COLOR"

  echo -e -n  "  - stackrox - collector " 
  # get init bundle
  curl -ks https://stackrox.$domain/v1/cluster-init/init-bundles -H 'accept: application/json, text/plain, */*' -H "authorization: Bearer $ROX_API_TOKEN" -H 'content-type: application/json' -d '{"name":"rancher"}' |jq -r .helmValuesBundle | base64 -D > cluster_init_bundle.yaml

  helm upgrade -i -n stackrox --create-namespace stackrox-secured-cluster-services rhacs/secured-cluster-services -f cluster_init_bundle.yaml --set clusterName=rancher --set centralEndpoint=central.stackrox:443 --set scanner.disable=true  > /dev/null 2>&1

  rm -rf cluster_init_bundle.yaml
  echo -e "$GREEN""ok" "$NO_COLOR"
}

############################# fleet ################################
function fleet () {
  # fix the local cluster in the group issue
  echo -e -n " fleet-ing "
  kubectl patch clusters.fleet.cattle.io -n fleet-local local --type=merge -p '{"metadata": {"labels":{"name":"local"}}}' > /dev/null 2>&1
  kubectl apply -f https://raw.githubusercontent.com/clemenko/fleet/main/gitrepo.yml > /dev/null 2>&1
  echo -e "$GREEN""ok" "$NO_COLOR"
}

############################# demo ################################
function demo () {
  echo -e " demo-ing "

  # echo -e -n " - whoami ";kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/whoami.yml > /dev/null 2>&1; echo -e "$GREEN""ok" "$NO_COLOR"

  # echo -e -n " - flask ";kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/flask_simple.yml > /dev/null 2>&1; echo -e "$GREEN""ok" "$NO_COLOR"
  
  # echo -e -n " - ghost ";kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/ghost.yaml > /dev/null 2>&1; echo -e "$GREEN""ok" "$NO_COLOR"

  echo -e -n " - gitea "
    helm upgrade -i gitea gitea-charts/gitea --namespace gitea --create-namespace --set gitea.admin.password=Pa22word --set gitea.admin.username=gitea --set persistence.size=500Mi --set postgresql.persistence.size=500Mi --set gitea.config.server.ROOT_URL=http://git.$domain --set gitea.config.server.DOMAIN=git.$domain > /dev/null 2>&1

    curl -s https://raw.githubusercontent.com/clemenko/k8s_yaml/master/gitea_traefik.yaml | sed "s/rfed.io/$domain/g" | kubectl apply -f - > /dev/null 2>&1;

    # mirror github
    until [ $(curl -s http://git.$domain/explore/repos| grep "<title>" | wc -l) = 1 ]; do sleep 2; echo -n "."; done
    curl -X POST http://git.$domain/api/v1/repos/migrate -H 'accept: application/json' -H 'authorization: Basic Z2l0ZWE6UGEyMndvcmQ=' -H 'Content-Type: application/json' -d '{ "clone_addr": "https://github.com/clemenko/fleet", "repo_name": "fleet","repo_owner": "gitea"}' > /dev/null 2>&1
  echo -e "$GREEN""ok" "$NO_COLOR"
  
  echo -e -n " - minio "
#   helm upgrade -i minio minio/minio --namespace minio --set rootUser=root,rootPassword=Pa22word --create-namespace --set mode=standalone --set resources.requests.memory=1Gi --set persistence.size=2Gi > /dev/null 2>&1
   # kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/minio.yml > /dev/null 2>&1
  # https://github.com/minio/minio/blob/master/helm/minio/values.yaml
#   kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/minio_traefik.yml > /dev/null 2>&1
   echo -e "$GREEN""ok" "$NO_COLOR"

 # echo -e -n " - jenkins "; kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/jenkins_containerd.yml > /dev/null 2>&1
   # curl -sk -X POST -u admin:$password https://stackrox.$domain/v1/apitokens/generate -d '{"name":"jenkins","role":null,"roles":["Continuous Integration"]}'| jq -r .token > jenkins_TOKEN
 # echo -e "$GREEN""ok" "$NO_COLOR"

 # echo -e -n " - harbor "
  #kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/harbor_traefik_ingress.yml > /dev/null 2>&1
 # echo -e "$GREEN""ok" "$NO_COLOR"

  echo -e -n " - code-server "
  rsync -avP ~/.kube/config root@$server:/opt/kube/config > /dev/null 2>&1
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/code-server.yml > /dev/null 2>&1
  echo -e "$GREEN""ok" "$NO_COLOR"

 #echo -e -n " - graylog "; kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/graylog.yaml > /dev/null 2>&1; echo -e "$GREEN""ok" "$NO_COLOR"

} 

################################ keycloak ##############################
# needs to be updated for Rancher!
function keycloak () {
  
  KEY_URL=keycloak.$domain
  RANCHER_URL=rancher.$domain

  echo -e " keycloaking"
  echo -e -n " - deploying "
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/keycloak.yml > /dev/null 2>&1
  echo -e "$GREEN""ok" "$NO_COLOR"
  
  echo -e -n " - waiting for url"

  until [ $(curl -sk https://keycloak.$domain/auth/ | grep "Administration Console" | wc -l) = 1 ]; do echo -e -n "." ; sleep 2; done
  echo -e "$GREEN"" ok" "$NO_COLOR"

  echo -e -n " - adding realm and client "

  # get auth token - notice keycloak's password 
  export key_token=$(curl -sk -X POST https://$KEY_URL/auth/realms/master/protocol/openid-connect/token -d 'client_id=admin-cli&username=admin&password='$password'&credentialId=&grant_type=password' | jq -r .access_token)

  # add realm
  curl -sk -X POST https://$KEY_URL/auth/admin/realms -H "authorization: Bearer $key_token" -H 'accept: application/json, text/plain, */*' -H 'content-type: application/json;charset=UTF-8' -d '{"enabled":true,"id":"rancher","realm":"rancher"}'

  # add client
  curl -sk -X POST https://$KEY_URL/auth/admin/realms/rancher/clients -H "authorization: Bearer $key_token" -H 'accept: application/json, text/plain, */*' -H 'content-type: application/json;charset=UTF-8' -d '{"enabled":true,"attributes":{},"redirectUris":[],"clientId":"rancher","protocol":"openid-connect","publicClient": false,"redirectUris":["https://'$RANCHER_URL'/verify-auth"]}'
  #,"implicitFlowEnabled":true

  # get client id
  export client_id=$(curl -sk  https://$KEY_URL/auth/admin/realms/rancher/clients/ -H "authorization: Bearer $key_token"  | jq -r '.[] | select(.clientId=="rancher") | .id')

  # get client_secret
  export client_secret=$(curl -sk  https://$KEY_URL/auth/admin/realms/rancher/clients/$client_id/client-secret -H "authorization: Bearer $key_token" | jq -r .value)

  # add mappers
  curl -sk -X POST https://$KEY_URL/auth/admin/realms/rancher/clients/$client_id/protocol-mappers/models -H "authorization: Bearer $key_token" -H 'accept: application/json, text/plain, */*' -H 'content-type: application/json;charset=UTF-8' -d '{"protocol":"openid-connect","config":{"full.path":"true","id.token.claim":"false","access.token.claim":"false","userinfo.token.claim":"true","claim.name":"groups"},"name":"Groups Mapper","protocolMapper":"oidc-group-membership-mapper"}'

  curl -sk -X POST https://$KEY_URL/auth/admin/realms/rancher/clients/$client_id/protocol-mappers/models -H "authorization: Bearer $key_token" -H 'accept: application/json, text/plain, */*' -H 'content-type: application/json;charset=UTF-8' -d '{"protocol":"openid-connect","config":{"id.token.claim":"false","access.token.claim":"true","included.client.audience":"rancher"},"name":"Client Audience","protocolMapper":"oidc-audience-mapper"}' 

  curl -sk -X POST https://$KEY_URL/auth/admin/realms/rancher/clients/$client_id/protocol-mappers/models -H "authorization: Bearer $key_token" -H 'accept: application/json, text/plain, */*' -H 'content-type: application/json;charset=UTF-8' -d '{"protocol":"openid-connect","config":{"full.path":"true","id.token.claim":"true","access.token.claim":"true","userinfo.token.claim":"true","claim.name":"full_group_path"},"name":"Group Path","protocolMapper":"oidc-group-membership-mapper"}'

  # add keycloak user clemenko / Pa22word
  curl -k 'https://keycloak.'$domain'/auth/admin/realms/rancher/users' -H 'Content-Type: application/json' -H "authorization: Bearer $key_token" -d '{"enabled":true,"attributes":{},"groups":[],"credentials":[{"type":"password","value":"Pa22word","temporary":false}],"username":"clemenko","emailVerified":"","firstName":"Andy","lastName":"Clemenko"}' 

  echo -e "$GREEN""ok" "$NO_COLOR"

  echo -e -n " - configuring rancher "
  # configure rancher
  token=$(curl -sk -X POST https://rancher.$domain/v3-public/localProviders/local?action=login -H 'content-type: application/json' -d '{"username":"admin","password":"'$password'"}' | jq -r .token)

  api_token=$(curl -sk https://rancher.$domain/v3/token -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"type":"token","description":"automation"}' | jq -r .token)

  curl -sk -X PUT https://rancher.$domain/v3/keyCloakOIDCConfigs/keycloakoidc?action=testAndEnable -H 'accept: application/json' -H 'accept-language: en-US,en;q=0.9' -H 'content-type: application/json;charset=UTF-8' -H 'content-type: application/json' -H "Authorization: Bearer $api_token" -X PUT -d '{"enabled":true,"id":"keycloakoidc","name":"keycloakoidc","type":"keyCloakOIDCConfig","accessMode":"unrestricted","rancherUrl":"https://rancher.'$domain'/verify-auth","scope":"openid profile email","clientId":"rancher","clientSecret":"'$client_secret'","issuer":"https://keycloak.'$domain'/auth/realms/rancher","authEndpoint":"https://keycloak.'$domain'/auth/realms/rancher/protocol/openid-connect/auth"}' > /dev/null 2>&1

  echo -e "$GREEN""ok" "$NO_COLOR"

#  export ROX_URL=stackrox.$domain
  # config stackrox
#  export auth_id=$(curl -sk -X POST -u admin:$password https://$ROX_URL/v1/authProviders -d '{"type":"oidc","uiEndpoint":"'$ROX_URL'","enabled":true,"config":{"mode":"query","do_not_use_client_secret":"false","client_secret":"'$client_secret'","issuer":"https+insecure://'$KEY_URL'/auth/realms/stackrox","client_id":"stackrox"},"name":"stackrox"}' | jq -r .id)

  # change default to Analyst
#  curl -sk -X POST -u admin:$password https://$ROX_URL/v1/groups -d '{"props":{"authProviderId":"'$auth_id'"},"roleName":"Analyst"}'

}

############################# slides ################################
function slides () {
  echo -e -n " slides "
  rsync -avP /Users/clemenko/Dropbox/work/talks/markdown/* root@$server:/opt/slides > /dev/null 2>&1
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/slides.yml > /dev/null 2>&1
  echo -e "$GREEN""ok" "$NO_COLOR"
}

############################## kill ################################
#remove the vms
function kill () {

if [ ! -z $(dolist | awk '{printf $3","}' | sed 's/,$//') ]; then
  echo -e -n " killing it all "
  #for i in $(dolist | awk '{print $2}'); do doctl compute droplet delete --force $i; done
  harvester vm delete $(harvester vm |grep -v NAME | awk '{printf $2" "}') > /dev/null 2>&1
  for i in $(dolist | awk '{print $3}'); do ssh-keygen -q -R $i > /dev/null 2>&1; done
  for i in $(doctl compute domain records list $domain|grep $prefix |awk '{print $1}'); do doctl compute domain records delete -f $domain $i; done
  until [ $(dolist | wc -l | sed 's/ //g') == 0 ]; do echo -e -n "."; sleep 2; done
  for i in $(doctl compute volume list --no-header |awk '{print $1}'); do doctl compute volume delete -f $i; done

  rm -rf *.txt *.log *.zip *.pub env.* certs backup.tar ~/.kube/config central* sensor* *token kubeconfig *TOKEN 

else
  echo -e -n " no cluster found "
fi

echo -e "$GREEN" "ok" "$NO_COLOR"
}

############################# usage ################################
function usage () {
  echo -e ""
  echo -e "-------------------------------------------------"
  echo -e ""
  echo -e " Usage: $0 {up|kill|tl|rancher|demo|full}"
  echo -e ""
  echo -e "${BLUE} ./k3s.sh up # build the vms ${NO_COLOR}"
  echo -e " ./k3s.sh tl # traefik and longhorn"
  echo -e " ${RED}./k3s.sh rancher # rancher will build cluster if not present${NO_COLOR}"
  echo -e " ./k3s.sh demo # deploy demo apps"
  echo -e " ./k3s.sh fleet # deploy fleet apps"
  echo -e " ./k3s.sh kill # kill the vms"
  echo -e " ./k3s.sh full # full send"
  echo -e ""
  echo -e "-------------------------------------------------"
  echo -e ""
  exit 1
}

case "$1" in
        up) up;;
        tl) up && traefik && longhorn;;
        kill) kill;;
        rox) rox;;
        neu) neu;;
        dolist) dolist;;
        traefik) traefik;;
        keycloak) keycloak;;
        longhorn) longhorn;;
        rancher) rancher;;
        demo) demo;;
        fleet) fleet;;
        slides) slides;;
        full) up && traefik && sleep 5 && longhorn && rancher && demo && slides;;
        *) usage;;
esac
