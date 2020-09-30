#!/bin/bash
# https://github.com/clemenko/rancher/blob/master/k3s.sh
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

image=ubuntu-20-04-x64
orchestrator=k3s

#stackrox automation.
stackrox_lic="stackrox.lic"
export REGISTRY_USERNAME=andy@stackrox.com

# Please set this before runing the script.
#export REGISTRY_PASSWORD=

######  NO MOAR EDITS #######
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
NORMAL=$(tput sgr0)
BLUE=$(tput setaf 4)

if [ "$image" = rancheros ]; then user=rancher; else user=root; fi
if [ "$orchestrator" = k3s ]; then prefix=k3s; else prefix=rancher; fi

#better error checking
command -v doctl >/dev/null 2>&1 || { echo "$RED" " ** Doctl was not found. Please install. ** " "$NORMAL" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "$RED" " ** Curl was not found. Please install. ** " "$NORMAL" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "$RED" " ** Jq was not found. Please install. ** " "$NORMAL" >&2; exit 1; }
command -v pdsh >/dev/null 2>&1 || { echo "$RED" " ** Pdsh was not found. Please install. ** " "$NORMAL" >&2; exit 1; }
command -v uuid >/dev/null 2>&1 || { echo "$RED" " ** Uuid was not found. Please install. ** " "$NORMAL" >&2; exit 1; }
command -v k3sup >/dev/null 2>&1 || { echo "$RED" " ** K3sup was not found. Please install. ** " "$NORMAL" >&2; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "$RED" " ** Kubectl was not found. Please install. ** " "$NORMAL" >&2; exit 1; }

################################# up ################################
function up () {
export PDSH_RCMD_TYPE=ssh
build_list=""
uuid=""

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
echo -n " building vms - $build_list "
doctl compute droplet create $build_list --region $zone --image $image --size $size --ssh-keys $key --tag-name k8s:worker --wait > /dev/null 2>&1
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
worker1=$(sed -n 2p hosts.txt|awk '{printf $1}')
worker2=$(sed -n 3p hosts.txt|awk '{printf $1}')

#update DNS
echo -n " updating dns"
doctl compute domain records create $domain --record-type A --record-name $prefix --record-ttl 300 --record-data $server > /dev/null 2>&1
doctl compute domain records create $domain --record-type CNAME --record-name "*" --record-ttl 150 --record-data $prefix.$domain. > /dev/null 2>&1
echo "$GREEN" "ok" "$NORMAL"

#host modifications and Docker install
if [[ "$image" = *"ubuntu"* ]]; then
  echo -n " updating the os "
  pdsh -l $user -w $host_list 'apt update; export DEBIAN_FRONTEND=noninteractive; apt upgrade -y; apt autoremove -y ' > /dev/null 2>&1
  #$(lsb_release -cs)
  echo "$GREEN" "ok" "$NORMAL"
fi

#or deploy k3s
if [ "$orchestrator" = k3s ]; then
  echo -n " deploying k3s "
  k3sup install --ip $server --user $user --k3s-extra-args '--no-deploy traefik' --cluster  > /dev/null 2>&1
  k3sup join --ip $worker1 --server-ip $server --user $user  > /dev/null 2>&1
  k3sup join --ip $worker2 --server-ip $server --user $user  > /dev/null 2>&1
  mv kubeconfig ~/.kube/config
  echo "$GREEN" "ok" "$NORMAL"
fi

echo " - install complete -"
echo ""

status
}

################################ longhorn ##############################
function longhorn () {
  echo -n  "  - longhorn "
  kubectl apply -f https://raw.githubusercontent.com/longhorn/longhorn/master/deploy/longhorn.yaml > /dev/null 2>&1
  kubectl patch storageclass longhorn -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}' > /dev/null 2>&1
  if [ "$orchestrator" = k3s ]; then kubectl patch storageclass local-path -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"false"}}}' > /dev/null 2>&1; fi

  #wait for longhorn to initiaize
  until [ $(kubectl get pod -n longhorn-system | grep -v 'Running\|NAME' | wc -l) = 0 ]; do echo -n "." ; sleep 2; done
  echo "$GREEN" "ok" "$NORMAL"
}

################################ rox ##############################
function rox () {
  echo " deploying :"

# ensure no central-bundle is not present
  if [ -d central-bundle ]; then
    echo "$RED" "Warning - cental-bundle already detected..." "$NORMAL"
    exit
  fi

# check for credentials for help.stackrox.com 
  if [ "$REGISTRY_USERNAME" = "" ] || [ "$REGISTRY_PASSWORD" = "" ]; then echo "Please setup a ENVs for REGISTRY_USERNAME and REGISTRY_PASSWORD..."; exit; fi

# non-pvc # roxctl central generate k8s none --license stackrox.lic --enable-telemetry=false --lb-type np --password $password > /dev/null 2>&1

# deploy traefik
  echo -n  "  - traefik"
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/traefik_crd_deployment.yml > /dev/null 2>&1
  echo "$GREEN" "ok" "$NORMAL"

# deploy longhorn
  longhorn

  echo -n  "  - stackrox "  
# generate stackrox yaml
  roxctl central generate k8s pvc --storage-class longhorn --license stackrox.lic --enable-telemetry=false --lb-type np --password $password > /dev/null 2>&1

# setup and install central
  ./central-bundle/central/scripts/setup.sh > /dev/null 2>&1
  kubectl apply -R -f central-bundle/central > /dev/null 2>&1

 # get the server and port from kubectl - assuming nodeport
  server=$(kubectl get nodes -o json | jq -r '.items[0].status.addresses[] | select( .type=="InternalIP" ) | .address ')
  rox_port=$(kubectl -n stackrox get svc central-loadbalancer |grep Node|awk '{print $5}'|sed -e 's/443://g' -e 's#/TCP##g')
  
# wait for central to be up
  until [ $(curl -kIs https://$server:$rox_port|head -n1|wc -l) = 1 ]; do echo -n "." ; sleep 2; done
  
# setup and install scanner
  ./central-bundle/scanner/scripts/setup.sh > /dev/null 2>&1
  kubectl apply -R -f central-bundle/scanner/ > /dev/null 2>&1

# ask central for a sensor bundle
  roxctl sensor generate k8s -e $server:$rox_port --name k3s --central central.stackrox:443 --insecure-skip-tls-verify --collection-method kernel-module -p $password > /dev/null 2>&1
  #--admission-controller-enabled

# install sensors
  ./sensor-k3s/sensor.sh > /dev/null 2>&1

# deploy traefik CRD IngressRoute
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/stackrox_traefik_crd.yml > /dev/null 2>&1

  echo "$GREEN" "ok" "$NORMAL"
  echo "  - dashboard - $BLUE https://stackrox.$domain $NORMAL"
}

############################# demo ################################
function demo () {
  command -v linkerd >/dev/null 2>&1 || { echo "$RED" " ** Linkerd was not found. Please install ** " "$NORMAL" >&2; exit 1; }

  echo -n "  - whoami ";kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/whoami.yml > /dev/null 2>&1; echo "$GREEN""ok" "$NORMAL"
  echo -n "  - struts ";kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/bad_struts.yml > /dev/null 2>&1; echo "$GREEN""ok" "$NORMAL"
  echo -n "  - flask ";kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/flask.yml > /dev/null 2>&1; echo "$GREEN""ok" "$NORMAL"
  
  echo -n "  - jenkins "; kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/jenkins_containerd.yml > /dev/null 2>&1; echo "$GREEN""ok" "$NORMAL"
  echo -n "  - creating jenkins api token "
  curl -sk -X POST -u admin:$password https://stackrox.$domain/v1/apitokens/generate -d '{"name":"jenkins","role":null,"roles":["Continuous Integration"]}'| jq -r .token > jenkins_API_TOKEN
  echo "$GREEN""ok" "$NORMAL"
  
  echo -n "  - linkerd "; 
  linkerd install | sed "s/localhost|/linkerd.$domain|localhost|/g" | kubectl apply -f - > /dev/null 2>&1
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/linkerd_traefik.yml > /dev/null 2>&1
  echo "$GREEN""ok" "$NORMAL"

  echo -n "  - prometheus "
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/prometheus/prometheus.yml > /dev/null 2>&1
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/prometheus/kube-state-metrics-complete.yml > /dev/null 2>&1
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/prometheus/prometheus_grafana_dashboards.yml > /dev/null 2>&1
  echo "$GREEN""ok" "$NORMAL"

  echo -n "  - patching stackrox for prometheus "
  kubectl -n stackrox patch svc/sensor -p '{"spec":{"ports":[{"name":"monitoring","port":9090,"protocol":"TCP","targetPort":9090}]}, "metadata":{"annotations":{"prometheus.io.scrape": "true", "prometheus.io/port": "9090"}}}' > /dev/null 2>&1

  kubectl -n stackrox patch svc/central -p '{"spec":{"ports":[{"name":"monitoring","port":9090,"protocol":"TCP","targetPort":9090}]}, "metadata":{"annotations":{"prometheus.io.scrape": "true", "prometheus.io/port": "9090"}}}' > /dev/null 2>&1

  # Modify network policies to allow ingress
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/stackrox_prometheus.yml > /dev/null 2>&1
  echo "$GREEN""ok" "$NORMAL"
} 

############################## kill ################################
#remove the vms
function kill () {

if [ -f hosts.txt ]; then
  echo -n " killing it all "
  for i in $(awk '{print $2}' hosts.txt); do doctl compute droplet delete --force $i; done
  for i in $(awk '{print $1}' hosts.txt); do ssh-keygen -q -R $i > /dev/null 2>&1; done
  for i in $(doctl compute domain records list dockr.life|grep 'k3s\|rancher'|awk '{print $1}'); do doctl compute domain records delete -f dockr.life $i; done

  rm -rf *.txt *.log *.zip *.pem *.pub env.* backup.tar ~/.kube/config central* sensor* *token kubeconfig *TOKEN
else
  echo -n " no hosts file found "
fi

echo "$GREEN" "ok" "$NORMAL"
}

############################# full ################################
function full () {
  if [ "$REGISTRY_USERNAME" = "" ] || [ "$REGISTRY_PASSWORD" = "" ]; then echo "Please setup a ENVs for REGISTRY_USERNAME and REGISTRY_PASSWORD..."; exit; fi
  up; rox; demo
}

############################# status ################################
function status () {
  echo " --- Cluster ---"
  doctl compute droplet list --no-header|grep $prefix
  echo ""

  if [ "$orchestrator" = rancher ]; then
    echo " - Rancher  : https://rancher.$domain"
    echo " - username : admin"
    echo " - password : "$password
    echo ""
  fi
}

############################# usage ################################
function usage () {
  echo ""
  echo "-------------------------------------------------"
  echo ""
  echo " Usage: $0 {up|kill|rox|status|demo|full}"
  echo ""
  echo " ./rancher.sh up # build the vms "
  echo " ./rancher.sh rox # deploy the good stuff"
  echo " ./rancher.sh kill # kill the vms"
  echo " ./rancher.sh status # get vm status"
  echo " ./rancher.sh demo # deploy demo apps"
  echo " ./rancher.sh full # full send"
  echo ""
  echo "-------------------------------------------------"
  echo ""
  exit 1
}

case "$1" in
        up) up;;
        kill) kill;;
        status) status;;
        rox) rox;;
        demo) demo;;
        full) full;;
        *) usage;;
esac
