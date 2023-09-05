#!/usr/bin/env bash

# functions

############################# usage ################################
function usage () {
  echo -e ""
  echo -e "-------------------------------------------------"
  echo -e ""
  echo -e " Usage: $0 {up|kill|tl|rancher|demo|full}"
  echo -e ""
  echo -e "${BLUE} $0 up # build the vms ${NO_COLOR}"
  echo -e " ${RED}$0 rancher # rancher will build cluster if not present${NO_COLOR}"
  echo -e " $0 demo # deploy demo apps"
  echo -e " $0 fleet # deploy fleet apps"
  echo -e " $0 kill # kill the vms"
  echo -e " $0 full # full send"
  echo -e ""
  echo -e "-------------------------------------------------"
  echo -e ""
  exit 1
}

############################# os_packages ################################
function centos_packages () {
# adding centos packages.
echo -e -n " adding os packages"
pdsh -l root -w $host_list 'echo -e "[keyfile]\nunmanaged-devices=interface-name:cali*;interface-name:flannel*" > /etc/NetworkManager/conf.d/rke2-canal.conf; yum install -y nfs-utils cryptsetup iscsi-initiator-utils; systemctl enable --now iscsid; #yum update -y' > /dev/null 2>&1
echo -e "$GREEN" "ok" "$NO_COLOR"
}

############################# carbide_reg ################################
function carbide_reg () {
# adding carbide reg
echo -e -n " adding carbide reg"
pdsh -l root -w $host_list 'mkdir -p /etc/rancher/{rke2,k3s}/; echo -e "mirrors:\n  rgcrprod.azurecr.us:\n    endpoint:\n      - https://rgcrprod.azurecr.us\nconfigs:\n  rgcrprod.azurecr.us:\n    auth:\n      username: "'$CARBIDEUSER'"\n      password: "'$CARBIDEPASS'"" > /etc/rancher/rke2/registries.yaml; rsync -avP /etc/rancher/rke2/registries.yaml /etc/rancher/k3s/' > /dev/null 2>&1
echo -e "$GREEN" "ok" "$NO_COLOR"
}

############################# kernel ################################
function kernel () {
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

# disable ipv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
sysctl -p' > /dev/null 2>&1
echo -e "$GREEN" "ok" "$NO_COLOR"
}

################################ rancher ##############################
function rancher () {

  if [[ -z $(dolist | awk '{printf $3","}' | sed 's/,$//') ]] && ! kubectl get node > /dev/null 2>&1 ; then
    echo -e "$BLUE" "Building cluster first." "$NO_COLOR"
    up && longhorn
  fi

  echo -e "$BLUE" "deploying rancher" "$NO_COLOR"
  #helm repo add rancher-latest https://releases.rancher.com/server-charts/latest --force-update > /dev/null 2>&1
  #helm repo add carbide-charts https://rancherfederal.github.io/carbide-charts --force-update > /dev/null 2>&1
  #helm repo add jetstack https://charts.jetstack.io --force-update > /dev/null 2>&1

  echo -e -n " - helm - cert-manager "
  helm upgrade -i cert-manager jetstack/cert-manager -n cert-manager --create-namespace --set installCRDs=true > /dev/null 2>&1 
  
  echo -e "$GREEN" "ok" "$NO_COLOR"
  
  echo -e -n " - helm - rancher "

if [ $domain = "rfed.io" ]; then 
  # custom TLS certs
  kubectl create ns cattle-system > /dev/null 2>&1 
  # kubectl -n cattle-system create secret tls tls-rancher-ingress --cert=tls.crt --key=tls.key
  kubectl -n cattle-system create secret tls tls-rancher-ingress --cert=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.cert --key=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.key > /dev/null 2>&1 
  # kubectl -n cattle-system create secret generic tls-ca --from-file=cacerts.pem
  kubectl -n cattle-system create secret generic tls-ca --from-file=/Users/clemenko/Dropbox/work/rfed.me/io/cacerts.pem > /dev/null 2>&1 
  # kubectl -n cattle-system create secret generic tls-ca-additional --from-file=ca-additional.pem=cacerts.pem

  # non carbide
  #helm upgrade -i rancher rancher-latest/rancher -n cattle-system --create-namespace --set hostname=rancher.$domain --set bootstrapPassword=bootStrapAllTheThings --set replicas=1 --set auditLog.level=2 --set auditLog.destination=hostPath --set ingress.tls.source=secret --set ingress.tls.secretName=tls-rancher-ingress --set privateCA=true > /dev/null 2>&1

  # carbide all the things - official certs
  helm upgrade -i rancher carbide-charts/rancher -n cattle-system --create-namespace --set hostname=rancher.$domain --set bootstrapPassword=bootStrapAllTheThings --set replicas=1 --set auditLog.level=2 --set auditLog.destination=hostPath --set "carbide.whitelabel.image=rgcrprod.azurecr.us/carbide/carbide-whitelabel" --set systemDefaultRegistry=rgcrprod.azurecr.us --set ingress.tls.source=secret --set ingress.tls.secretName=tls-rancher-ingress --set privateCA=true  > /dev/null 2>&1 
  # --version=v2.7.4

  else
   # self signed certs
    helm upgrade -i rancher carbide-charts/rancher -n cattle-system --create-namespace --set hostname=rancher.$domain --set bootstrapPassword=bootStrapAllTheThings --set replicas=1 --set auditLog.level=2 --set auditLog.destination=hostPath --set "carbide.whitelabel.image=rgcrprod.azurecr.us/carbide/carbide-whitelabel" --set systemDefaultRegistry=rgcrprod.azurecr.us > /dev/null 2>&1 

  fi
 
  echo -e "$GREEN" "ok" "$NO_COLOR"

  # wait for rancher
  echo -e -n " - waiting for rancher "
  until [ $(curl -sk https://rancher.$domain/v3-public/authtokens | grep uuid | wc -l) = 1 ]; do 
    sleep 2
    echo -e -n "." 
    done
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
  token=$(curl -sk -X POST https://rancher.$domain/v3-public/localProviders/local?action=login -H 'content-type: application/json' -d '{"username":"admin","password":"bootStrapAllTheThings"}' | jq -r .token)

  curl -sk https://rancher.$domain/v3/users?action=changepassword -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"currentPassword":"bootStrapAllTheThings","newPassword":"'$password'"}'  > /dev/null 2>&1 

  api_token=$(curl -sk https://rancher.$domain/v3/token -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"type":"token","description":"automation"}' | jq -r .token)

  curl -sk https://rancher.$domain/v3/settings/server-url -H 'content-type: application/json' -H "Authorization: Bearer $api_token" -X PUT -d '{"name":"server-url","value":"https://rancher.'$domain'"}'  > /dev/null 2>&1

  curl -sk https://rancher.$domain/v3/settings/telemetry-opt -X PUT -H 'content-type: application/json' -H 'accept: application/json' -H "Authorization: Bearer $api_token" -d '{"value":"out"}' > /dev/null 2>&1
  echo -e "$GREEN" "ok" "$NO_COLOR"

  # carbide
  echo -e -n " - adding Carbide "

  # add offline docs
  helm upgrade -i airgapped-docs carbide-charts/airgapped-docs -n carbide-docs --create-namespace > /dev/null 2>&1

  kubectl create namespace carbide-stigatron-system > /dev/null 2>&1
  kubectl create secret generic stigatron-license -n carbide-stigatron-system --from-literal=license=$CARBIDELIC > /dev/null 2>&1 
  #--set "global.cattle.systemDefaultRegistry=YOUR_REGISTRY_HERE"

  token=$(curl -sk -X POST https://rancher.$domain/v3-public/localProviders/local?action=login -H 'content-type: application/json' -d '{"username":"admin","password":"'$password'"}' | jq -r .token)

  # enable extension
  curl -sk https://rancher.$domain/v1/catalog.cattle.io.clusterrepos -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"type":"catalog.cattle.io.clusterrepo","metadata":{"name":"rancher-ui-plugins"},"spec":{"gitBranch":"main","gitRepo":"https://github.com/rancher/ui-plugin-charts"}}' > /dev/null 2>&1
  
  # add extension
  curl -sk https://rancher.$domain/v1/catalog.cattle.io.clusterrepos/rancher-charts?action=install -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"charts":[{"chartName":"ui-plugin-operator","version":"102.0.0+up0.2.0","releaseName":"ui-plugin-operator","annotations":{"catalog.cattle.io/ui-source-repo-type":"cluster","catalog.cattle.io/ui-source-repo":"rancher-charts"},"values":{"global":{"cattle":{"systemDefaultRegistry":"rgcrprod.azurecr.us"}}}}],"wait":true,"namespace":"cattle-ui-plugin-system"}' > /dev/null 2>&1

  # add extension
  curl -sk https://rancher.$domain/v1/catalog.cattle.io.clusterrepos/rancher-charts?action=install -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"charts":[{"chartName":"ui-plugin-operator-crd","version":"102.0.0+up0.2.0","releaseName":"ui-plugin-operator-crd","annotations":{"catalog.cattle.io/ui-source-repo-type":"cluster","catalog.cattle.io/ui-source-repo":"rancher-charts"},"values":{"global":{"cattle":{"systemDefaultRegistry":"rgcrprod.azurecr.us"}}}}],"wait":true,"namespace":"cattle-ui-plugin-system"}' > /dev/null 2>&1

  sleep 15

  # add sigatron-ui
  helm install -n carbide-stigatron-system --create-namespace stigatron-ui carbide-charts/stigatron-ui  > /dev/null 2>&1 #--set "global.cattle.systemDefaultRegistry=YOUR_REGISTRY_HERE"

  sleep 15

  # cis benchmarks
  curl -sk https://rancher.$domain/v1/catalog.cattle.io.clusterrepos/rancher-charts?action=install -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"charts":[{"chartName":"rancher-cis-benchmark-crd","version":"3.0.0","releaseName":"rancher-cis-benchmark-crd","projectId":null,"values":{"global":{"cattle":{"systemDefaultRegistry":"rgcrprod.azurecr.us","clusterId":"local","clusterName":"local","systemProjectId":"p-s8w4q","url":"https://rancher.'$domain'","rkePathPrefix":"","rkeWindowsPathPrefix":""},"systemDefaultRegistry":"rgcrprod.azurecr.us"}},"annotations":{"catalog.cattle.io/ui-source-repo-type":"cluster","catalog.cattle.io/ui-source-repo":"rancher-charts"}},{"chartName":"rancher-cis-benchmark","version":"3.0.0","releaseName":"rancher-cis-benchmark","annotations":{"catalog.cattle.io/ui-source-repo-type":"cluster","catalog.cattle.io/ui-source-repo":"rancher-charts"},"values":{"global":{"cattle":{"systemDefaultRegistry":"rgcrprod.azurecr.us","clusterId":"local","clusterName":"local","systemProjectId":"p-s8w4q","url":"https://rancher.'$domain'","rkePathPrefix":"","rkeWindowsPathPrefix":""},"systemDefaultRegistry":"rgcrprod.azurecr.us"}}}],"noHooks":false,"timeout":"600s","wait":true,"namespace":"cis-operator-system","projectId":null,"disableOpenAPIValidation":false,"skipCRDs":false}' > /dev/null 2>&1

  sleep 15

  # add stigatron operator
  helm install -n carbide-stigatron-system stigatron carbide-charts/stigatron  > /dev/null 2>&1 # --set "global.cattle.systemDefaultRegistry=YOUR_REGISTRY_HERE" --set "heimdall2.global.cattle.systemDefaultRegistry=YOUR_REGISTRY_HERE" 

  echo -e "$GREEN" "ok" "$NO_COLOR"
}

################################ longhorn ##############################
function longhorn () {
  echo -e -n  " - longhorn "
  # helm repo add longhorn https://charts.longhorn.io --force-update
  
  # to http basic auth --> https://longhorn.io/docs/1.4.1/deploy/accessing-the-ui/longhorn-ingress/

  # non carbide
  helm upgrade -i longhorn  longhorn/longhorn -n longhorn-system --create-namespace --set ingress.enabled=true --set ingress.host=longhorn.$domain --set default.storageMinimalAvailablePercentage=25 --set default.storageOverProvisioningPercentage=200  > /dev/null 2>&1  # --set defaultSettings.v2DataEngine=true --set persistence.defaultDataLocality="best-effort"

  # carbide all the things --set global.cattle.systemDefaultRegistry=rgcrprod.azurecr.us 

  sleep 5

  #wait for longhorn to initiaize
  until [ $(kubectl get pod -n longhorn-system | grep -v 'Running\|NAME' | wc -l) = 0 ] && [ "$(kubectl get pod -n longhorn-system | wc -l)" -gt 20 ] ; do echo -e -n "." ; sleep 2; done
  # testing out ` kubectl wait --for condition=containersready -n longhorn-system pod --all`

  kubectl patch storageclass longhorn -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}' > /dev/null 2>&1
  if [ "$prefix" = k3s ]; then kubectl patch storageclass local-path -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"false"}}}' > /dev/null 2>&1; fi

  # add encryption per volume storage class 
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/longhorn_encryption.yml > /dev/null 2>&1

  echo -e "$GREEN" "ok" "$NO_COLOR"
}

################################ neu ##############################
function neu () {
  echo -e -n  " - neuvector "
  
  # helm repo add neuvector https://neuvector.github.io/neuvector-helm/ --force-update
  
  # custom TLS certs
  kubectl create ns neuvector > /dev/null 2>&1 
  kubectl -n neuvector create secret tls tls-ingress --cert=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.cert --key=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.key > /dev/null 2>&1 
  kubectl -n neuvector create secret generic tls-ca --from-file=/Users/clemenko/Dropbox/work/rfed.me/io/cacerts.pem > /dev/null 2>&1 

  # clear
  helm upgrade -i neuvector -n neuvector neuvector/core --create-namespace --set k3s.enabled=true --set manager.svc.type=ClusterIP --set controller.pvc.enabled=true --set controller.pvc.capacity=500Mi --set internal.certmanager.enabled=true --set manager.runAsUser=1000 --set cve.updater.runAsUser=1000 --set cve.scanner.runAsUser=1000 --set manager.ingress.enabled=true --set manager.ingress.host=neuvector.$domain --set manager.ingress.tls=true --set manager.ingress.secretName=tls-ingress  > /dev/null 2>&1

  export govmessage="PGI+WW91IGFyZSBhY2Nlc3NpbmcgYSBVLlMuIEdvdmVybm1lbnQgKFVTRykgSW5mb3JtYXRpb24gU3lzdGVtIChJUykgdGhhdCBpcyBwcm92aWRlZCBmb3IgVVNHLWF1dGhvcml6ZWQgdXNlIG9ubHkuPC9iPjxicj4KPGJyPgpCeSB1c2luZyB0aGlzIElTICh3aGljaCBpbmNsdWRlcyBhbnkgZGV2aWNlIGF0dGFjaGVkIHRvIHRoaXMgSVMpLCB5b3UgY29uc2VudCB0byB0aGUgZm9sbG93aW5nIGNvbmRpdGlvbnM6PGJyPgo8YnI+Ci1UaGUgVVNHIHJvdXRpbmVseSBpbnRlcmNlcHRzIGFuZCBtb25pdG9ycyBjb21tdW5pY2F0aW9ucyBvbiB0aGlzIElTIGZvciBwdXJwb3NlcyBpbmNsdWRpbmcsIGJ1dCBub3QgbGltaXRlZCB0bywgcGVuZXRyYXRpb24gdGVzdGluZywgQ09NU0VDIG1vbml0b3JpbmcsIG5ldHdvcmsgb3BlcmF0aW9ucyBhbmQgZGVmZW5zZSwgcGVyc29ubmVsIG1pc2NvbmR1Y3QgKFBNKSwgbGF3IGVuZm9yY2VtZW50IChMRSksIGFuZCBjb3VudGVyaW50ZWxsaWdlbmNlIChDSSkgaW52ZXN0aWdhdGlvbnMuPGJyPgo8YnI+Ci1BdCBhbnkgdGltZSwgdGhlIFVTRyBtYXkgaW5zcGVjdCBhbmQgc2VpemUgZGF0YSBzdG9yZWQgb24gdGhpcyBJUy48YnI+Cjxicj4KLUNvbW11bmljYXRpb25zIHVzaW5nLCBvciBkYXRhIHN0b3JlZCBvbiwgdGhpcyBJUyBhcmUgbm90IHByaXZhdGUsIGFyZSBzdWJqZWN0IHRvIHJvdXRpbmUgbW9uaXRvcmluZywgaW50ZXJjZXB0aW9uLCBhbmQgc2VhcmNoLCBhbmQgbWF5IGJlIGRpc2Nsb3NlZCBvciB1c2VkIGZvciBhbnkgVVNHLWF1dGhvcml6ZWQgcHVycG9zZS48YnI+Cjxicj4KLVRoaXMgSVMgaW5jbHVkZXMgc2VjdXJpdHkgbWVhc3VyZXMgKGUuZy4sIGF1dGhlbnRpY2F0aW9uIGFuZCBhY2Nlc3MgY29udHJvbHMpIHRvIHByb3RlY3QgVVNHIGludGVyZXN0cy0tbm90IGZvciB5b3VyIHBlcnNvbmFsIGJlbmVmaXQgb3IgcHJpdmFjeS48YnI+Cjxicj4KLU5vdHdpdGhzdGFuZGluZyB0aGUgYWJvdmUsIHVzaW5nIHRoaXMgSVMgZG9lcyBub3QgY29uc3RpdHV0ZSBjb25zZW50IHRvIFBNLCBMRSBvciBDSSBpbnZlc3RpZ2F0aXZlIHNlYXJjaGluZyBvciBtb25pdG9yaW5nIG9mIHRoZSBjb250ZW50IG9mIHByaXZpbGVnZWQgY29tbXVuaWNhdGlvbnMsIG9yIHdvcmsgcHJvZHVjdCwgcmVsYXRlZCB0byBwZXJzb25hbCByZXByZXNlbnRhdGlvbiBvciBzZXJ2aWNlcyBieSBhdHRvcm5leXMsIHBzeWNob3RoZXJhcGlzdHMsIG9yIGNsZXJneSwgYW5kIHRoZWlyIGFzc2lzdGFudHMuIFN1Y2ggY29tbXVuaWNhdGlvbnMgYW5kIHdvcmsgcHJvZHVjdCBhcmUgcHJpdmF0ZSBhbmQgY29uZmlkZW50aWFsLiBTZWUgVXNlciBBZ3JlZW1lbnQgZm9yIGRldGFpbHMuIDxicj4gCg=="

  # Unclass
  # helm upgrade -i neuvector -n neuvector neuvector/core --create-namespace --set k3s.enabled=true --set manager.svc.type=ClusterIP --set controller.pvc.enabled=true --set controller.pvc.capacity=500Mi --set internal.certmanager.enabled=true --set manager.env.envs[0].name=CUSTOM_PAGE_HEADER_COLOR --set manager.env.envs[0].value="#007a33" --set manager.env.envs[1].name=CUSTOM_PAGE_HEADER_CONTENT --set manager.env.envs[1].value="VS8vRk9VTwo=" --set manager.env.envs[2].name=CUSTOM_PAGE_FOOTER_COLOR --set manager.env.envs[2].value="#007a33" --set manager.env.envs[3].name=CUSTOM_PAGE_FOOTER_CONTENT --set manager.env.envs[3].value="VS8vRk9VTwo=" --set manager.env.envs[4].name=CUSTOM_EULA_POLICY --set manager.env.envs[4].value=$govmessage > /dev/null 2>&1

  # TS
  # helm upgrade -i neuvector -n neuvector neuvector/core --create-namespace --set k3s.enabled=true --set manager.svc.type=ClusterIP --set controller.pvc.enabled=true --set controller.pvc.capacity=500Mi --set internal.certmanager.enabled=true --set manager.env.envs[0].name=CUSTOM_PAGE_HEADER_COLOR --set manager.env.envs[0].value="#fce83a" --set manager.env.envs[1].name=CUSTOM_PAGE_HEADER_CONTENT --set manager.env.envs[1].value="VE9QIFNFQ1JFVC8vU0NJCg==" --set manager.env.envs[2].name=CUSTOM_PAGE_FOOTER_COLOR --set manager.env.envs[2].value="#fce83a" --set manager.env.envs[3].name=CUSTOM_PAGE_FOOTER_CONTENT --set manager.env.envs[3].value="VE9QIFNFQ1JFVC8vU0NJCg==" --set manager.env.envs[4].name=CUSTOM_EULA_POLICY --set manager.env.envs[4].value=$govmessage

  until [[ "$(curl -skL -H "Content-Type: application/json" -o /dev/null -w '%{http_code}' https://neuvector.$domain/auth -d '{"username": "admin", "password": "admin"}')" == "200" ]]; do echo -e -n .; sleep 1; done

  TOKEN=$(curl -sk -H "Content-Type: application/json" https://neuvector.$domain/auth -d '{"username": "admin", "password": "admin"}' | jq  -r .token.token)

  curl -sk -H "Content-Type: application/json" -H 'Token: '$TOKEN https://neuvector.$domain/eula -d '{"accepted":true}' > /dev/null 2>&1

  curl -sk -H "Content-Type: application/json" -H 'Token: '$TOKEN -X PATCH https://neuvector.$domain/user -d '{"domain_permissions":{},"server":"","email":"","role":"admin","username":"admin","default_password":true,"password_days_until_expire":-1,"global_permissions":[{"id":"config","read":true,"write":true},{"id":"nv_resource","read":true,"write":true},{"id":"rt_scan","read":true,"write":true},{"id":"reg_scan","read":true,"write":true},{"id":"ci_scan","read":false,"write":true},{"id":"cloud","read":true,"write":true},{"id":"rt_policy","read":true,"write":true},{"id":"admctrl","read":true,"write":true},{"id":"compliance","read":true,"write":true},{"id":"audit_events","read":true,"write":false},{"id":"security_events","read":true,"write":false},{"id":"events","read":true,"write":false},{"id":"authentication","read":true,"write":true},{"id":"authorization","read":true,"write":true},{"id":"vulnerability","read":true,"write":true}],"locale":"en","fullname":"admin","token":"'$TOKEN'","timeout":300,"modify_password":false,"password":"admin","new_password":"'$password'"}' > /dev/null 2>&1

  echo -e "$GREEN" "ok" "$NO_COLOR"
}

############################# fleet ################################
function fleet () {
  echo -e -n " fleet-ing "
  kubectl apply -f https://raw.githubusercontent.com/clemenko/fleet/main/gitrepo.yml > /dev/null 2>&1
  echo -e "$GREEN""ok" "$NO_COLOR"
}

############################# demo ################################
function demo () {
  echo -e " demo-ing "

  # echo -e -n " - whoami ";kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/whoami.yml > /dev/null 2>&1; echo -e "$GREEN""ok" "$NO_COLOR"

  # echo -e -n " - flask ";kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/flask_simple.yml > /dev/null 2>&1; echo -e "$GREEN""ok" "$NO_COLOR"
  
  # echo -e -n " - ghost ";kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/ghost.yaml > /dev/null 2>&1; echo -e "$GREEN""ok" "$NO_COLOR"
  
   echo -e -n " - minio "
   # helm repo add minio https://charts.min.io/ --force-update
   helm upgrade -i minio minio/minio -n minio --set rootUser=admin,rootPassword=$password --create-namespace --set mode=standalone --set resources.requests.memory=1Gi --set persistence.size=1Gi --set mode=standalone --set ingress.enabled=true --set ingress.hosts[0]=s3.$domain --set consoleIngress.enabled=true --set consoleIngress.hosts[0]=minio.$domain > /dev/null 2>&1
   echo -e "$GREEN""ok" "$NO_COLOR"

  echo -e -n " - harbor "
  # helm repo add harbor https://helm.goharbor.io --force-update
  helm upgrade -i harbor harbor/harbor -n harbor --create-namespace --set expose.tls.enabled=false --set expose.tls.auto.commonName=harbor.$domain --set expose.ingress.hosts.core=harbor.$domain --set persistence.enabled=true --set harborAdminPassword=$password --set externalURL=http://harbor.$domain --set notary.enabled=false > /dev/null 2>&1;
  echo -e "$GREEN""ok" "$NO_COLOR"

  echo -e -n " - gitea "
  # helm repo add gitea-charts https://dl.gitea.io/charts/ --force-update
  helm upgrade -i gitea gitea-charts/gitea -n gitea --create-namespace --set gitea.admin.password=$password --set gitea.admin.username=gitea --set persistence.size=500Mi --set ingress.enabled=true --set ingress.hosts[0].host=git.$domain --set ingress.hosts[0].paths[0].path=/ --set ingress.hosts[0].paths[0].pathType=Prefix --set gitea.config.server.ROOT_URL=http://git.$domain --set gitea.config.server.DOMAIN=git.$domain --set postgresql-ha.enabled=false --set redis-cluster.enabled=false --set gitea.config.database.DB_TYPE=sqlite3 --set gitea.config.session.PROVIDER=memory  --set gitea.config.cache.ADAPTER=memory --set gitea.config.queue.TYPE=level > /dev/null 2>&1

  # mirror github
  until [ $(curl -s http://git.$domain/explore/repos| grep "<title>" | wc -l) = 1 ]; do sleep 2; echo -n "."; done

  sleep 5
  
  curl -X POST http://git.$domain/api/v1/repos/migrate -H 'accept: application/json' -H 'authorization: Basic Z2l0ZWE6UGEyMndvcmQ=' -H 'Content-Type: application/json' -d '{ "clone_addr": "https://github.com/clemenko/fleet", "repo_name": "fleet","repo_owner": "gitea"}' > /dev/null 2>&1
  echo -e "$GREEN""ok" "$NO_COLOR"

} 

################################ keycloak ##############################
# helm repo add bitnami https://charts.bitnami.com/bitnami --force-update

function keycloak () {
  
  KEY_URL=keycloak.$domain
  RANCHER_URL=rancher.$domain

  echo -e " keycloaking"
  echo -e -n " - deploying "
  
  kubectl create ns keycloak > /dev/null 2>&1 
  kubectl -n keycloak create secret tls tls-ingress --cert=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.cert --key=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.key > /dev/null 2>&1 
  # kubectl -n keycloak create secret generic tls-ca --from-file=/Users/clemenko/Dropbox/work/rfed.me/io/cacerts.pem > /dev/null 2>&1 

  curl -s https://raw.githubusercontent.com/clemenko/k8s_yaml/master/keycloak.yml  | sed "s/rfed.xx/$domain/g" | kubectl apply -f - > /dev/null 2>&1

  #helm upgrade -i keycloak  bitnami/keycloak --namespace keycloak --create-namespace --set auth.adminUser=admin --set auth.adminPassword=Pa22word > /dev/null 2>&1
  # --set ingress.enabled=true --set ingress.hostname=keycloak.$domain --set ingress.tls=true --set tls.enabled=true --set httpRelativePath="/"
  
  echo -e "$GREEN""ok" "$NO_COLOR"
  
  echo -e -n " - waiting for keycloak "

  until [ $(curl -sk https://$KEY_URL/ | grep "Administration Console" | wc -l) = 1 ]; do echo -e -n "." ; sleep 2; done
  echo -e "$GREEN"" ok" "$NO_COLOR"

  echo -e -n " - adding realm and client "

  # get auth token - notice keycloak's password 
  export key_token=$(curl -sk -X POST https://$KEY_URL/realms/master/protocol/openid-connect/token -d 'client_id=admin-cli&username=admin&password='$password'&credentialId=&grant_type=password' | jq -r .access_token)

  # add realm
  curl -sk -X POST https://$KEY_URL/admin/realms -H "authorization: Bearer $key_token" -H 'accept: application/json, text/plain, */*' -H 'content-type: application/json;charset=UTF-8' -d '{"enabled":true,"id":"rancher","realm":"rancher"}'

  # add client
  curl -sk -X POST https://$KEY_URL/admin/realms/rancher/clients -H "authorization: Bearer $key_token" -H 'accept: application/json, text/plain, */*' -H 'content-type: application/json;charset=UTF-8' -d '{"enabled":true,"attributes":{},"redirectUris":[],"clientId":"rancher","protocol":"openid-connect","publicClient": false,"redirectUris":["https://'$RANCHER_URL'/verify-auth"]}'
  #,"implicitFlowEnabled":true

  # get client id
  export client_id=$(curl -sk  https://$KEY_URL/admin/realms/rancher/clients/ -H "authorization: Bearer $key_token"  | jq -r '.[] | select(.clientId=="rancher") | .id')

  # get client_secret
  export client_secret=$(curl -sk  https://$KEY_URL/admin/realms/rancher/clients/$client_id/client-secret -H "authorization: Bearer $key_token" | jq -r .value)

  # add mappers
  curl -sk -X POST https://$KEY_URL/admin/realms/rancher/clients/$client_id/protocol-mappers/models -H "authorization: Bearer $key_token" -H 'accept: application/json, text/plain, */*' -H 'content-type: application/json;charset=UTF-8' -d '{"protocol":"openid-connect","config":{"full.path":"true","id.token.claim":"false","access.token.claim":"false","userinfo.token.claim":"true","claim.name":"groups"},"name":"Groups Mapper","protocolMapper":"oidc-group-membership-mapper"}'

  curl -sk -X POST https://$KEY_URL/admin/realms/rancher/clients/$client_id/protocol-mappers/models -H "authorization: Bearer $key_token" -H 'accept: application/json, text/plain, */*' -H 'content-type: application/json;charset=UTF-8' -d '{"protocol":"openid-connect","config":{"id.token.claim":"false","access.token.claim":"true","included.client.audience":"rancher"},"name":"Client Audience","protocolMapper":"oidc-audience-mapper"}' 

  curl -sk -X POST https://$KEY_URL/admin/realms/rancher/clients/$client_id/protocol-mappers/models -H "authorization: Bearer $key_token" -H 'accept: application/json, text/plain, */*' -H 'content-type: application/json;charset=UTF-8' -d '{"protocol":"openid-connect","config":{"full.path":"true","id.token.claim":"true","access.token.claim":"true","userinfo.token.claim":"true","claim.name":"full_group_path"},"name":"Group Path","protocolMapper":"oidc-group-membership-mapper"}'

  # add keycloak user clemenko / Pa22word
  curl -k 'https://'$KEY_URL'/admin/realms/rancher/users' -H 'Content-Type: application/json' -H "authorization: Bearer $key_token" -d '{"enabled":true,"attributes":{},"groups":[],"credentials":[{"type":"password","value":"'$password'","temporary":false}],"username":"clemenko","emailVerified":"","firstName":"Andy","lastName":"Clemenko"}' 

  echo -e "$GREEN""ok" "$NO_COLOR"

  echo -e -n " - configuring rancher "
  # configure rancher
  token=$(curl -sk -X POST https://$RANCHER_URL/v3-public/localProviders/local?action=login -H 'content-type: application/json' -d '{"username":"admin","password":"'$password'"}' | jq -r .token)

  api_token=$(curl -sk https://$RANCHER_URL/v3/token -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"type":"token","description":"automation"}' | jq -r .token)

  curl -sk -X PUT https://$RANCHER_URL/v3/keyCloakOIDCConfigs/keycloakoidc?action=testAndEnable -H 'accept: application/json' -H 'accept-language: en-US,en;q=0.9' -H 'content-type: application/json;charset=UTF-8' -H 'content-type: application/json' -H "Authorization: Bearer $api_token" -X PUT -d '{"enabled":true,"id":"keycloakoidc","name":"keycloakoidc","type":"keyCloakOIDCConfig","accessMode":"unrestricted","rancherUrl":"https://rancher.'$domain'/verify-auth","scope":"openid profile email","clientId":"rancher","clientSecret":"'$client_secret'","issuer":"https://keycloak.'$domain'/realms/rancher","authEndpoint":"https://'$KEY_URL'/realms/rancher/protocol/openid-connect/auth/"}' > /dev/null 2>&1

  echo -e "$GREEN""ok" "$NO_COLOR"

}
