#!/usr/bin/env bash

# https://github.com/clemenko/rke2
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
# s-8vcpu-16gb
domain=rfed.io

#image=ubuntu-22-04-x64
image=rockylinux-9-x64

# rancher / k8s
prefix=rke # no rke k3s
k8s_version=stable #latest
# curl -s https://update.rke2.io/v1-release/channels | jq '.data[] | select(.id=="stable") | .latest'

######  NO MOAR EDITS #######
#export PDSH_RCMD_TYPE=ssh

#better error checking
command -v doctl >/dev/null 2>&1 || { fatal "Doctl was not found. Please install" ; }
command -v curl >/dev/null 2>&1 || { fatal "Curl was not found. Please install" ; }
command -v jq >/dev/null 2>&1 || { fatal "Jq was not found. Please install" ; }
command -v pdsh >/dev/null 2>&1 || { fatal "Pdsh was not found. Please install" ; }
command -v k3sup >/dev/null 2>&1 || { fatal "K3sup was not found. Please install" ; }
command -v kubectl >/dev/null 2>&1 || { fatal "Kubectl was not found. Please install" ; }

#### doctl_list ####
function dolist () { doctl compute droplet list --no-header|grep $prefix |sort -k 2; }

source functions.sh

# update helm
helm repo update > /dev/null 2>&1

################################# up ################################
function up () {
build_list=""
# helm repo update > /dev/null 2>&1

if [[ -n "$(dolist)" ]]; then
  fatal "Warning - cluster already detected..."
  exit
fi

#rando list generation
for i in $(seq 1 $num); do build_list="$build_list $prefix$i"; done

#build VMS
echo -e -n " - building vms -$build_list"
doctl compute droplet create $build_list --region $zone --image $image --size $size --ssh-keys 30:98:4f:c5:47:c2:88:28:fe:3c:23:cd:52:49:51:01 --wait > /dev/null 2>&1 || fatal "vms did not build"
info_ok

#check for SSH
echo -e -n " - checking for ssh "
for ext in $(dolist | awk '{print $3}'); do
  until [ $(ssh -o ConnectTimeout=1 root@$ext 'exit' 2>&1 | grep 'timed out\|refused' | wc -l) = 0 ]; do echo -e -n "." ; sleep 5; done
done
info_ok

#get ips
host_list=$(dolist | awk '{printf $3","}' | sed 's/,$//')
server=$(dolist | sed -n 1p | awk '{print $3}')
worker_list=$(dolist | sed 1d | awk '{printf $3","}' | sed 's/,$//')

#update DNS
echo -e -n " - updating dns"
doctl compute domain records create $domain --record-type A --record-name $prefix --record-ttl 60 --record-data $server > /dev/null 2>&1
doctl compute domain records create $domain --record-type CNAME --record-name "*" --record-ttl 60 --record-data $prefix.$domain. > /dev/null 2>&1
info_ok

sleep 10

#host modifications
if [[ "$image" = *"ubuntu"* ]]; then
  echo -e -n " - adding os packages"
  pdsh -l root -w $host_list 'mkdir -p /opt/kube; systemctl stop ufw; systemctl disable ufw; echo -e "PubkeyAcceptedKeyTypes=+ssh-rsa" >> /etc/ssh/sshd_config; systemctl restart sshd; export DEBIAN_FRONTEND=noninteractive; apt update; apt install nfs-common -y;  #apt upgrade -y; apt autoremove -y' > /dev/null 2>&1
  info_ok
fi

if [[ "$image" = *"centos"* || "$image" = *"rocky"* || "$image" = *"alma"* ]]; then centos_packages; fi

#kernel tuning from functions
kernel

#or deploy k3s
if [ "$prefix" != k3s ] && [ "$prefix" != rke ]; then exit; fi

if [ "$prefix" = k3s ]; then
  echo -e -n " - deploying k3s"
  k3sup install --ip $server --user root --cluster --k3s-extra-args '' --k3s-channel $k8s_version --local-path ~/.kube/config > /dev/null 2>&1
  # --k3s-extra-args '--disable traefik'

  for workeri in $(dolist | sed 1d | awk '{print $3}'); do 
    k3sup join --ip $workeri --server-ip $server --user root --k3s-extra-args '' --k3s-channel $k8s_version > /dev/null 2>&1
  done 
  
  info_ok
fi

#or deploy rke2
if [ "$prefix" = rke ]; then
  echo -e -n "$BLUE" "deploying rke2" "$NO_COLOR"

  # systemctl disable nm-cloud-setup.service nm-cloud-setup.timer
  
  ssh root@$server 'mkdir -p /var/lib/rancher/rke2/server/manifests/ /etc/rancher/rke2/; useradd -r -c "etcd user" -s /sbin/nologin -M etcd -U; echo -e "apiVersion: audit.k8s.io/v1\nkind: Policy\nmetadata:\n  name: rke2-audit-policy\nrules:\n  - level: Metadata\n    resources:\n    - group: \"\"\n      resources: [\"secrets\"]\n  - level: RequestResponse\n    resources:\n    - group: \"\"\n      resources: [\"*\"]" > /etc/rancher/rke2/audit-policy.yaml; echo -e "#profile: cis\n#selinux: true\nsecrets-encryption: true\ntoken: bootstrapAllTheThings\ntls-san:\n- rke."'$domain'"\nwrite-kubeconfig-mode: 0600\n#pod-security-admission-config-file: /etc/rancher/rke2/rancher-psact.yaml\nkube-controller-manager-arg:\n- bind-address=127.0.0.1\n- use-service-account-credentials=true\n- tls-min-version=VersionTLS12\n- tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\nkube-scheduler-arg:\n- tls-min-version=VersionTLS12\n- tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\nkube-apiserver-arg:\n- tls-min-version=VersionTLS12\n- tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n- authorization-mode=RBAC,Node\n- anonymous-auth=false\n- audit-policy-file=/etc/rancher/rke2/audit-policy.yaml\n- audit-log-mode=blocking-strict\n- audit-log-maxage=30\nkubelet-arg:\n- kube-reserved=cpu=400m,memory=1Gi\n- system-reserved=cpu=400m,memory=1Gi\n- protect-kernel-defaults=true\n- read-only-port=0\n- authorization-mode=Webhook\n- streaming-connection-idle-timeout=5m\n- max-pods=400" > /etc/rancher/rke2/config.yaml;  curl -s https://raw.githubusercontent.com/clemenko/k8s_yaml/master/rancher-psact.yaml -o /etc/rancher/rke2/rancher-psact.yaml ; echo -e "apiVersion: helm.cattle.io/v1\nkind: HelmChartConfig\nmetadata:\n  name: rke2-ingress-nginx\n  namespace: kube-system\nspec:\n  valuesContent: |-\n    controller:\n      config:\n        use-forwarded-headers: true\n      extraArgs:\n        enable-ssl-passthrough: true" > /var/lib/rancher/rke2/server/manifests/rke2-ingress-nginx-config.yaml; curl -sfL https://get.rke2.io | INSTALL_RKE2_CHANNEL='$k8s_version' sh - ; systemctl enable --now rke2-server.service' > /dev/null 2>&1

  sleep 15

  pdsh -l root -w $worker_list 'curl -sfL https://get.rke2.io | INSTALL_RKE2_CHANNEL='$k8s_version' INSTALL_RKE2_TYPE=agent sh - && echo -e "selinux: true\nserver: https://"'$server'":9345\ntoken: bootstrapAllTheThings\nprofile: cis\nkubelet-arg:\n- protect-kernel-defaults=true\n- read-only-port=0\n- authorization-mode=Webhook" > /etc/rancher/rke2/config.yaml; systemctl enable --now rke2-agent.service' > /dev/null 2>&1

  ssh root@$server cat /etc/rancher/rke2/rke2.yaml | sed -e "s/127.0.0.1/$server/g" > ~/.kube/config 
  chmod 0600 ~/.kube/config

  info_ok
fi

echo -e -n " - cluster active "
sleep 10
until [ $(kubectl get node|grep NotReady|wc -l) = 0 ]; do echo -e -n "."; sleep 2; done
sleep 10
info_ok
}

############################## kill ################################
#remove the vms
function kill () {

if [ ! -z $(dolist | awk '{printf $3","}' | sed 's/,$//') ]; then
  echo -e -n " killing it all "
  for i in $(dolist | awk '{print $2}'); do doctl compute droplet delete --force $i; done
  for i in $(dolist | awk '{print $3}'); do ssh-keygen -q -R $i > /dev/null 2>&1; done
  for i in $(doctl compute domain records list $domain|grep $prefix |awk '{print $1}'); do doctl compute domain records delete -f $domain $i; done
  until [ $(dolist | wc -l | sed 's/ //g') == 0 ]; do echo -e -n "."; sleep 2; done
  for i in $(doctl compute volume list --no-header |awk '{print $1}'); do doctl compute volume delete -f $i; done

  rm -rf *.txt *.log *.zip *.pub env.* certs backup.tar ~/.kube/config central* sensor* *token kubeconfig *TOKEN 

else
  echo -e -n " no cluster found "
fi

info_ok
}

case "$1" in
        up) up;;
        kill) kill;;
        px) portworx;;
        dolist) dolist;;
        keycloak) keycloak;;
        longhorn) longhorn;;
        rancher) rancher;;
        demo) demo;;
        fleet) fleet;;
        *) usage;;
esac
