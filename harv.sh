#!/usr/bin/env bash

# this script assumes you have harvester setup
# you need harvester, kubectl, uuid, jq, k3sup, pdsh and curl installed.
# clemenko@gmail.com 

###################################
# edit varsw
###################################
set -e
num=6
export password=Pa22word
export domain=rfed.site

template=rocky9

# rancher / k8s
prefix=rke- # no rke k3s
rke2_channel=v1.25 #latest

# ingress nginx or traefik
ingress=traefik # traefik

# stackrox automation
export REGISTRY_USERNAME=AndyClemenko
# export REGISTRY_PASSWORD= # set on the command line 

# Carbide creds
export CARBIDEUSER=andy-clemenko-read-token
#export CARBIDEPASS=  # set on the command line

######  NO MOAR EDITS #######
export RED='\x1b[0;31m'
export GREEN='\x1b[32m'
export BLUE='\x1b[34m'
export YELLOW='\x1b[33m'
export NO_COLOR='\x1b[0m'
export PDSH_RCMD_TYPE=ssh

#better error checking
command -v curl >/dev/null 2>&1 || { echo -e "$RED" " ** Curl was not found. Please install. ** " "$NO_COLOR" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo -e "$RED" " ** Jq was not found. Please install. ** " "$NO_COLOR" >&2; exit 1; }
command -v pdsh >/dev/null 2>&1 || { echo -e "$RED" " ** Pdsh was not found. Please install. ** " "$NO_COLOR" >&2; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo -e "$RED" " ** Kubectl was not found. Please install. ** " "$NO_COLOR" >&2; exit 1; }

#### doctl_list ####
function dolist () { harvester vm |grep -v NAME | grep Run | grep $prefix| awk '{print $1"  "$2"  "$6"  "$4"  "$5}'; }

source functions.sh

################################# up ################################
function up () {
build_list=""
# helm repo update > /dev/null 2>&1

if [ ! -z $(dolist) ]; then
  echo -e "$RED" "Warning - cluster already detected..." "$NO_COLOR"
  exit
fi

#build VMS
echo -e -n " building vms -$build_list "
harvester vm create --template $template --count $num rke > /dev/null 2>&1
until [ $(dolist | grep "192.168" | wc -l) = $num ]; do echo -e -n "." ; sleep 2; done
sleep 10

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

# update node list
node1=$(dolist | sed -n 1p | awk '{print $3}')
node2=$(dolist | sed -n 2p | awk '{print $3}')
node3=$(dolist | sed -n 3p | awk '{print $3}')
worker_list=$(dolist | sed '1,3d'  | awk '{printf $3","}' | sed -e 's/,$//')

# update DNS
echo -e -n " updating dns"
doctl compute domain records create $domain --record-type A --record-name $prefix"1" --record-ttl 60 --record-data $node1 > /dev/null 2>&1
doctl compute domain records create $domain --record-type A --record-name rke --record-ttl 60 --record-data $node1 > /dev/null 2>&1
doctl compute domain records create $domain --record-type A --record-name rke --record-ttl 60 --record-data $node2 > /dev/null 2>&1
doctl compute domain records create $domain --record-type A --record-name rke --record-ttl 60 --record-data $node3 > /dev/null 2>&1
doctl compute domain records create $domain --record-type CNAME --record-name "*" --record-ttl 60 --record-data rke.$domain. > /dev/null 2>&1
echo -e "$GREEN" "ok" "$NO_COLOR"

sleep 10

centos_packages

carbide_reg

kernel

#or deploy k3s
if [ "$prefix" != rke- ]; then exit; fi

echo -e -n " deploying rke2 "
if [ "$ingress" = nginx ]; then ingress_file="#disable: rke2-ingress-nginx"; else ingress_file="disable: rke2-ingress-nginx"; fi

ssh root@$node1 'mkdir -p /etc/rancher/rke2/ /var/lib/rancher/rke2/server/manifests/; useradd -r -c "etcd user" -s /sbin/nologin -M etcd -U; echo -e "apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n- level: RequestResponse" > /etc/rancher/rke2/audit-policy.yaml; echo -e "'$ingress_file'\n#profile: cis-1.6\nselinux: true\nsecrets-encryption: true\ntls-san:\n- rke.'$domain'\nwrite-kubeconfig-mode: 0600\nuse-service-account-credentials: true\nkube-controller-manager-arg:\n- bind-address=127.0.0.1\n- use-service-account-credentials=true\n- tls-min-version=VersionTLS12\n- tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\nkube-apiserver-arg:\n- tls-min-version=VersionTLS12\n- tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\n- authorization-mode=RBAC,Node\n- anonymous-auth=false\n- audit-policy-file=/etc/rancher/rke2/audit-policy.yaml\n- audit-log-mode=blocking-strict\n- audit-log-maxage=30\nkubelet-arg:\n- protect-kernel-defaults=true\n- read-only-port=0\n- authorization-mode=Webhook\n- streaming-connection-idle-timeout=5m" > /etc/rancher/rke2/config.yaml ; echo -e "apiVersion: helm.cattle.io/v1\nkind: HelmChartConfig\nmetadata:\n  name: rke2-ingress-nginx\n  namespace: kube-system\nspec:\n  valuesContent: |-\n    controller:\n      config:\n        use-forwarded-headers: true\n      extraArgs:\n        enable-ssl-passthrough: true" > /var/lib/rancher/rke2/server/manifests/rke2-ingress-nginx-config.yaml; curl -sfL https://get.rke2.io | INSTALL_RKE2_CHANNEL='$rke2_channel' sh - && systemctl enable --now  rke2-server.service' > /dev/null 2>&1

sleep 10

token=$(ssh root@$node1 'cat /var/lib/rancher/rke2/server/node-token')

pdsh -l root -w $node2,$node3 'mkdir -p /etc/rancher/rke2/ /var/lib/rancher/rke2/server/manifests/; useradd -r -c "etcd user" -s /sbin/nologin -M etcd -U; echo -e "apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n- level: RequestResponse" > /etc/rancher/rke2/audit-policy.yaml; echo -e "server: https://'$node1':9345\ntoken: '$token'\n'$ingress_file'\n#profile: cis-1.6\nselinux: true\nsecrets-encryption: true\ntls-san:\n- rke.'$domain'\nwrite-kubeconfig-mode: 0600\nkube-controller-manager-arg:\n- bind-address=127.0.0.1\n- use-service-account-credentials=true\n- tls-min-version=VersionTLS12\n- tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\nkube-apiserver-arg:\n- tls-min-version=VersionTLS12\n- tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\n- authorization-mode=RBAC,Node\n- anonymous-auth=false\n- audit-policy-file=/etc/rancher/rke2/audit-policy.yaml\n- audit-log-mode=blocking-strict\n- audit-log-maxage=30\nkubelet-arg:\n- protect-kernel-defaults=true\n- read-only-port=0\n- authorization-mode=Webhook" > /etc/rancher/rke2/config.yaml ; echo -e "apiVersion: helm.cattle.io/v1\nkind: HelmChartConfig\nmetadata:\n  name: rke2-ingress-nginx\n  namespace: kube-system\nspec:\n  valuesContent: |-\n    controller:\n      config:\n        use-forwarded-headers: true\n      extraArgs:\n        enable-ssl-passthrough: true" > /var/lib/rancher/rke2/server/manifests/rke2-ingress-nginx-config.yaml;  curl -sfL https://get.rke2.io | INSTALL_RKE2_CHANNEL='$rke2_channel' sh - && systemctl enable --now  rke2-server.service' > /dev/null 2>&1

sleep 10

pdsh -l root -w $worker_list 'yum install -y http://dl.rockylinux.org/pub/rocky/9.1/AppStream/x86_64/os/Packages/c/container-selinux-2.189.0-1.el9.noarch.rpm; curl -sfL https://get.rke2.io | INSTALL_RKE2_CHANNEL='$rke2_channel' INSTALL_RKE2_TYPE=agent sh - && mkdir -p /etc/rancher/rke2/ && echo -e "selinux: true\nserver: https://rke.'$domain':9345\ntoken: '$token'\nwrite-kubeconfig-mode: 0600\n#profile: cis-1.6\nkube-apiserver-arg:\n- authorization-mode=RBAC,Node\nkubelet-arg:\n- protect-kernel-defaults=true\n- read-only-port=0\n- authorization-mode=Webhook" > /etc/rancher/rke2/config.yaml && systemctl enable --now rke2-agent.service' > /dev/null 2>&1

ssh root@$server cat /etc/rancher/rke2/rke2.yaml | sed  -e "s/127.0.0.1/$server/g" > ~/.kube/config 
chmod 0600 ~/.kube/config

echo -e "$GREEN" "ok" "$NO_COLOR"

echo -e -n " - cluster active "
sleep 5
until [ $(kubectl get node|grep NotReady|wc -l) = 0 ]; do echo -e -n "."; sleep 2; done
echo -e "$GREEN" "ok" "$NO_COLOR"
}

############################## kill ################################
#remove the vms
function kill () {

if [ ! -z $(dolist | awk '{printf $3","}' | sed 's/,$//') ]; then
  echo -e -n " killing it all "
  harvester vm delete $(harvester vm |grep -v NAME | grep $prefix | awk '{printf $2" "}') > /dev/null 2>&1
  for i in $(dolist | awk '{print $3}'); do ssh-keygen -q -R $i > /dev/null 2>&1; done
  for i in $(doctl compute domain records list $domain|grep rke |awk '{print $1}'); do doctl compute domain records delete -f $domain $i; done
  until [ $(dolist | wc -l | sed 's/ //g') == 0 ]; do echo -e -n "."; sleep 2; done
  for i in $(doctl compute volume list --no-header |awk '{print $1}'); do doctl compute volume delete -f $i; done

  rm -rf *.txt *.log *.zip *.pub env.* certs backup.tar ~/.kube/config central* sensor* *token kubeconfig *TOKEN 

else
  echo -e -n " no cluster found "
fi

echo -e "$GREEN" "ok" "$NO_COLOR"
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
        *) usage;;
esac
