#!/bin/bash
#https://github.com/clemenko/rancher/blob/master/rancher.sh
###################################
# edit vars
###################################
set -e
num=3
password=Pa22word
zone=nyc1
size=s-4vcpu-8gb
key=30:98:4f:c5:47:c2:88:28:fe:3c:23:cd:52:49:51:01
domain=dockr.life

#image=centos-7-x64
image=ubuntu-19-10-x64

orchestrator=k3s
#orchestrator=rancher

#stackrox
stackrox_lic="stackrox.lic"
export REGISTRY_USERNAME=andy@stackrox.com
#REGISTRY_PASSWORD=

######  NO MOAR EDITS #######
################################# up ################################
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
NORMAL=$(tput sgr0)

if [ "$image" = rancheros ]; then user=rancher; else user=root; fi
if [ "$orchestrator" = k3s ]; then prefix=k3s; else prefix=rancher; fi

#better error checking
command -v curl >/dev/null 2>&1 || { echo "$RED" " ** Curl was not found. Please install. ** " "$NORMAL" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "$RED" " ** Jq was not found. Please install. ** " "$NORMAL" >&2; exit 1; }
command -v pdsh >/dev/null 2>&1 || { echo "$RED" " ** Pdsh was not found. Please install. ** " "$NORMAL" >&2; exit 1; }
command -v uuid >/dev/null 2>&1 || { echo "$RED" " ** Uuid was not found. Please install. ** " "$NORMAL" >&2; exit 1; }
command -v k3sup >/dev/null 2>&1 || { echo "$RED" " ** K3sup was not found. Please install. ** " "$NORMAL" >&2; exit 1; }

function up () {
export PDSH_RCMD_TYPE=ssh
build_list=""
uuid=""

if [ -f hosts.txt ]; then
  echo "$RED" "Warning - cluster already detected..." "$NORMAL"
  exit
fi

for i in $(seq 1 $num); do
 uuid=$(uuid -v4| awk -F"-" '{print $4}')
 build_list="$prefix-$uuid $build_list"
done
echo -n " building vms - $build_list "
doctl compute droplet create $build_list --region $zone --image $image --size $size --ssh-keys $key --tag-name k8s:worker --wait > /dev/null 2>&1
doctl compute droplet list|grep -v ID|grep $prefix|awk '{print $3" "$2}'> hosts.txt

echo "$GREEN" "[ok]" "$NORMAL"

echo -n " checking for ssh "
for ext in $(awk '{print $1}' hosts.txt); do
  until [ $(ssh -o ConnectTimeout=1 $user@$ext 'exit' 2>&1 | grep 'timed out\|refused' | wc -l) = 0 ]; do echo -n "." ; sleep 5; done
done
echo "$GREEN" "[ok]" "$NORMAL"

host_list=$(awk '{printf $1","}' hosts.txt|sed 's/,$//')
server=$(sed -n 1p hosts.txt|awk '{print $1}')
worker1=$(sed -n 2p hosts.txt|awk '{printf $1}')
worker2=$(sed -n 3p hosts.txt|awk '{printf $1}')

echo -n " updating dns"
doctl compute domain records create $domain --record-type A --record-name $prefix --record-ttl 300 --record-data $server > /dev/null 2>&1
doctl compute domain records create $domain --record-type CNAME --record-name "*" --record-ttl 150 --record-data $prefix.$domain. > /dev/null 2>&1
echo "$GREEN" "[ok]" "$NORMAL"

if [[ "$image" == *"centos"* ]]; then
  echo -n " updating the os and installing docker "
  pdsh -l $user -w $host_list 'setenforce 0; sed -i s/best=True/best=False/g /etc/dnf/dnf.conf; yum update -y; yum install -y yum-utils; yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo; yum install docker-ce -y; systemctl start docker; systemctl enable docker' > /dev/null 2>&1
  echo "$GREEN" "[ok]" "$NORMAL"
fi

if [[ "$image" = *"ubuntu"* ]]; then
 echo -n " updating the os and installing docker "
 pdsh -l $user -w $host_list 'apt update; export DEBIAN_FRONTEND=noninteractive; apt install -y apt-transport-https ca-certificates curl gnupg-agent; software-properties-common; curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -; add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable"; apt update; apt install -y docker-ce docker-ce-cli containerd.io; systemctl start docker; systemctl enable docker; #apt upgrade -y; apt autoremove -y ' > /dev/null 2>&1
 #$(lsb_release -cs)

 echo "$GREEN" "[ok]" "$NORMAL"
fi

echo -n " updating kernel settings "
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
echo "$GREEN" "[ok]" "$NORMAL"

echo -n " adding daemon configs "
pdsh -l $user -w $host_list 'echo -e "{\n \"selinux-enabled\": false, \n \"log-driver\": \"json-file\", \n \"log-opts\": {\"max-size\": \"10m\", \"max-file\": \"3\"} \n}" > /etc/docker/daemon.json; systemctl restart docker'
echo "$GREEN" "[ok]" "$NORMAL"

if [ "$orchestrator" = rancher ]; then
  echo -n " starting rancher server "
  ssh $user@$server "docker run -d -p 80:80 -p 443:443 --restart=unless-stopped rancher/rancher" > /dev/null 2>&1

  until curl $server:443 > /dev/null 2>&1; do echo -n .; sleep 2; done
  sleep 2
  echo "$GREEN" "[ok]" "$NORMAL"

  echo -n " setting up rancher server "
  until [ "$token" != "" ]; do 
    token=$(curl -sk https://$server/v3-public/localProviders/local?action=login -H 'content-type: application/json' -d '{"username":"admin","password":"admin"}'| jq -r .token) > /dev/null 2>&1
  done

  curl -sk https://$server/v3/users?action=changepassword -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"currentPassword":"admin","newPassword":"'$password'"}'  > /dev/null 2>&1 
  
  api_token=$(curl -sk https://$server/v3/token -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"type":"token","description":"automation"}' | jq -r .token)
  echo $api_token > api_token
  
  curl -sk https://$server/v3/settings/server-url -H 'content-type: application/json' -H "Authorization: Bearer $api_token" -X PUT -d '{"name":"server-url","value":"https://'$server'"}'  > /dev/null 2>&1
  
  curl -sk https://$server/v3/settings/telemetry-opt -X PUT -H 'content-type: application/json' -H 'accept: application/json' -H "Authorization: Bearer $api_token" -d '{"value":"out"}' > /dev/null 2>&1
  echo "$GREEN" "[ok]" "$NORMAL"

  echo -n " attaching agents "
  agent_list=$(sed -n 2,"$num"p hosts.txt|awk '{printf $1","}')

  # Create cluster
  clusterid=$(curl -sk https://$server/v3/cluster -H 'content-type: application/json' -H "Authorization: Bearer $api_token" -d '{"type":"cluster","nodes":[],"rancherKubernetesEngineConfig":{"ignoreDockerVersion":true},"name":"rancher"}' | jq -r .id )

  # Generate token (clusterRegistrationToken) and extract nodeCommand
  agent_command=$(curl -sk https://$server/v3/clusterregistrationtoken -H 'content-type: application/json' -H "Authorization: Bearer $api_token" --data-binary '{"type":"clusterRegistrationToken","clusterId":"'$clusterid'"}' | jq -r .nodeCommand)

  ssh $user@$server "$agent_command --etcd --controlplane --worker" > /dev/null 2>&1
  pdsh -l $user -w $agent_list "$agent_command --worker" > /dev/null 2>&1
  echo "$GREEN" "[ok]" "$NORMAL"

  echo -n " setting up kubectl "
  curl -sk https://$server/v3/clusters/$clusterid?action=generateKubeconfig -X POST -H 'accept: application/json' -H "Authorization: Bearer $api_token" | jq -r .config > ~/.kube/config
  echo "$GREEN" "[ok]" "$NORMAL"
fi

if [ "$orchestrator" = k3s ]; then
  echo -n " setting up k3s cluster "
  k3sup install --ip $server --user $user --k3s-extra-args '--no-deploy traefik --docker' --cluster  > /dev/null 2>&1
  k3sup join --ip $worker1 --server-ip $server --user $user --k3s-extra-args '--docker'  > /dev/null 2>&1
  k3sup join --ip $worker2 --server-ip $server --user $user --k3s-extra-args '--docker'  > /dev/null 2>&1
  mv kubeconfig ~/.kube/config
  echo "$GREEN" "[ok]" "$NORMAL"
fi

if [[ "$image" == *"centos"* ]]; then
  echo -n " building nfs server for pv "
  nfs_list=$(awk '{printf $1" "}' hosts.txt|sed 's/,$//')
  nfs_opts=$(echo -n "/opt/nfs"; for i in $nfs_list; do echo -n " $i(rw,sync,no_root_squash,no_all_squash)"; done )
  ssh root@$server 'mkdir /opt/nfs; chmod -R 777 /opt/nfs; yum -y install nfs-utils; systemctl enable rpcbind nfs-server; systemctl start rpcbind nfs-server ; echo "'$nfs_opts'" > /etc/exports; systemctl restart nfs-server' > /dev/null 2>&1
  echo "$GREEN" "[ok]" "$NORMAL"
fi

echo ""
echo "========= Rancher install complete ========="
echo ""

status
}

################################ rox ##############################
function rox () {
  echo -n " setting up stackrox "

  if [ -d central-bundle ]; then
    echo "$RED" "Warning - cental-bundle already detected..." "$NORMAL"
    exit
  fi

  if [ "$REGISTRY_USERNAME" = "" ] || [ "$REGISTRY_PASSWORD" = "" ]; then echo "Please setup a ENVs for REGISTRY_USERNAME and REGISTRY_PASSWORD..."; exit; fi

  server=$(sed -n 1p hosts.txt|awk '{print $1}')

  roxctl central generate k8s none --license stackrox.lic --enable-telemetry=false --lb-type np --password $password > /dev/null 2>&1
#FOR HELM
#  roxctl central generate k8s none --output-format helm --license stackrox.lic --enable-telemetry=false --lb-type np --password $password > /dev/null 2>&1

  # move the nodeport to 30200
  sed -i '' $'s/targetPort: api/targetPort: api\\\n    nodePort: 30200/g' central-bundle/central/loadbalancer.yaml > /dev/null 2>&1

  ./central-bundle/central/scripts/setup.sh > /dev/null 2>&1
  kubectl apply -R -f central-bundle/central > /dev/null 2>&1
  rox_port=$(kubectl -n stackrox get svc central-loadbalancer |grep Node|awk '{print $5}'|sed -e 's/443://g' -e 's#/TCP##g')
  
  until [ $(curl -kIs https://$server:$rox_port|head -n1|wc -l) = 1 ]; do echo -n "." ; sleep 2; done
  
  roxctl sensor generate k8s -e $server:$rox_port --name rancher --central central.stackrox:443 --insecure-skip-tls-verify --collection-method kernel-module -p $password > /dev/null 2>&1

  kubectl apply -R -f central-bundle/scanner/ > /dev/null 2>&1
  ./sensor-rancher/sensor.sh > /dev/null 2>&1

  echo "$GREEN" " [ok]" "$NORMAL"
  echo " - dashboard - https://rancher.$domain:$rox_port"
}

############################## kill ################################
function kill () {

if [ -f hosts.txt ]; then
  echo -n " killing it all "
  for i in $(awk '{print $2}' hosts.txt); do doctl compute droplet delete --force $i; done
  for i in $(awk '{print $1}' hosts.txt); do ssh-keygen -q -R $i > /dev/null 2>&1; done
  for i in $(doctl compute domain records list dockr.life|grep 'k3s\|rancher'|awk '{print $1}'); do doctl compute domain records delete -f dockr.life $i; done

  rm -rf *.txt *.log *.zip *.pem *.pub env.* backup.tar ~/.kube/config central* sensor* *token kubeconfig
else
  echo -n " no hosts file found "
fi

echo "$GREEN" "[ok]" "$NORMAL"
}

############################# status ################################
function status () {
  echo "===== Cluster ====="
  doctl compute droplet list |grep $prefix
  echo ""

  if [ "$orchestrator" = rancher ]; then
    echo "===== Dashboards ====="
    echo " - Rancher  : https://rancher.dockr.life"
    echo " - username : admin"
    echo " - password : "$password
  fi 

  echo ""
}

case "$1" in
        up) up;;
        kill) kill;;
        status) status;;
        rox) rox;;
        config) config;;
        *) echo "Usage: $0 {up|kill|rox|config|status}"; exit 1
esac
