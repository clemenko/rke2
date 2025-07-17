#!/usr/bin/env bash

# functions
# color
export RED='\x1b[0;31m'
export GREEN='\x1b[32m'
export BLUE='\x1b[34m'
export YELLOW='\x1b[33m'
export NO_COLOR='\x1b[0m'

# set functions for debugging/logging
function info { echo -e "$GREEN[info]$NO_COLOR $1" ;  }
function warn { echo -e "$YELLOW[warn]$NO_COLOR $1" ; }
function fatal { echo -e "$RED[error]$NO_COLOR $1" ; exit 1 ; }
function info_ok { echo -e "$GREEN"" ok""$NO_COLOR" ; }

#gov logon message
export govmessage=$(cat <<EOF
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.By using this IS (which includes any device attached to this IS), you consent to the following conditions:-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.-At any time, the USG may inspect and seize data stored on this IS.-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
EOF
)


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
echo -e -n " - adding os packages"
pdsh -l root -w $host_list 'echo -e "[keyfile]\nunmanaged-devices=interface-name:cali*;interface-name:flannel*" > /etc/NetworkManager/conf.d/rke2-canal.conf; yum install -y nfs-utils cryptsetup iscsi-initiator-utils; systemctl enable --now iscsid; yum update openssh -y; #yum update -y' > /dev/null 2>&1
info_ok
}

############################# kernel ################################
function kernel () {
#kernel tuning
echo -e -n " - updating kernel settings"
pdsh -l root -w $host_list 'cat << EOF >> /etc/sysctl.conf
# SWAP settings
vm.swappiness=0
vm.panic_on_oom=0
vm.overcommit_memory=1
kernel.panic=10
kernel.panic_on_oops=1
vm.max_map_count = 262144
net.ipv4.ip_local_port_range=1024 65000
net.core.somaxconn=10000
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15
net.core.somaxconn=4096
net.core.netdev_max_backlog=4096
net.core.rmem_max=536870912
net.core.wmem_max=536870912
net.ipv4.tcp_max_syn_backlog=20480
net.ipv4.tcp_max_tw_buckets=400000
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_rmem=4096 87380 268435456
net.ipv4.tcp_wmem=4096 87380 268435456
net.ipv4.tcp_syn_retries=2
net.ipv4.tcp_synack_retries=2
net.ipv4.neigh.default.gc_thresh1=8096
net.ipv4.neigh.default.gc_thresh2=12288
net.ipv4.neigh.default.gc_thresh3=16384
net.ipv4.tcp_keepalive_time=600
net.ipv4.ip_forward=1
fs.inotify.max_user_instances=8192
fs.inotify.max_user_watches=1048576
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
sysctl -p' > /dev/null 2>&1
info_ok
}

################################ portworx ##############################
function portworx () {

# from https://gist.github.com/clemenko/00dcbb344476aafda18dbae207952d71

# add volumes
echo -e -n " - px - checking volumes"
if [ "$(doctl compute volume list --no-header | wc -l | xargs )" != 0 ]; then echo -e -n " "$GREEN"- detected -";

else
  echo -e -n " - adding"
  for num in 1 2 3; do
    doctl compute volume-action attach $(doctl compute volume create port$num --region nyc1 --size 60GiB | grep -v ID| awk '{print $1}') $(doctl compute droplet list | grep rke$num | awk '{print $1}') > /dev/null 2>&1
  done
fi

info_ok

echo -e -n " - px - adding operator and storagecluster - "$RED"can take about 10 min"$NO_COLOR""
# operator
echo -e -n " ."
kubectl apply -f 'https://install.portworx.com/?comp=pxoperator&kbver=1.31.0&ns=portworx' > /dev/null 2>&1
sleep 15
echo -e -n " ."
kubectl wait --for condition=containersready -n portworx pod --all > /dev/null 2>&1

# StorageCluster spec
echo -e -n " ."
kubectl apply -f 'https://install.portworx.com/3.3?operator=true&mc=false&kbver=1.31.0&ns=portworx&b=true&iop=6&c=px-cluster1&stork=true&csi=true&mon=true&tel=false&st=k8s&promop=true' > /dev/null 2>&1 
sleep 30
echo -e -n " ."
kubectl wait --for condition=Ready -n portworx pod --all --timeout=3000s   > /dev/null 2>&1

# make a default storage class
echo -e -n " ."
until [ $(kubectl get sc | grep px-csi | wc -l | xargs) = 8 ]; do sleep 5; done
kubectl patch storageclass px-csi-db -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}' > /dev/null 2>&1 

info_ok

echo -e -n " - px - adding central"

helm repo add portworx http://charts.portworx.io/ --force-update > /dev/null 2>&1

helm upgrade -i px-central portworx/px-central --namespace px-central --create-namespace --set persistentStorage.enabled=true,persistentStorage.storageClassName="px-csi-db",service.pxCentralUIServiceType="ClusterIP",pxbackup.enabled=true,pxmonitor.enabled=false,installCRDs=true > /dev/null 2>&1

until [ $(kubectl get pod -n px-central | wc -l | xargs ) = 18 ]; do sleep 5; done

cat <<EOF | kubectl apply -n px-central -f - > /dev/null 2>&1 
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: px-central-ui
  namespace: px-central
spec:
  rules:
  - host: central.rfed.io
    http:
      paths:
      - backend:
          service:
            name: px-central-ui
            port:
              number: 80
        path: /
        pathType: ImplementationSpecific
EOF

info_ok

echo -e -n " - px - adding grafana"

export PX_URL="https://docs.portworx.com/samples/portworx-enterprise/k8s/pxc"

# create config maps
kubectl create configmap -n portworx  grafana-dashboard-config --from-literal=grafana-dashboard-config.yaml="$(curl -sk $PX_URL/grafana-dashboard-config.yaml)" > /dev/null 2>&1
kubectl create configmap -n portworx  grafana-source-config --from-literal=grafana-dashboard-config.yaml="$(curl -sk $PX_URL/grafana-datasource.yaml)" > /dev/null 2>&1

# dashboards
kubectl -n portworx create configmap grafana-dashboards \
--from-literal=portworx-cluster-dashboard.json="$(curl -sk $PX_URL/portworx-cluster-dashboard.json)" \
--from-literal=portworx-performance-dashboard.json="$(curl -sk $PX_URL/portworx-performance-dashboard.json)" \
--from-literal=portworx-node-dashboard.json="$(curl -sk $PX_URL/portworx-node-dashboard.json)" \
--from-literal=portworx-volume-dashboard.json="$(curl -sk $PX_URL/portworx-volume-dashboard.json)" \
--from-literal=portworx-etcd-dashboard.json="$(curl -sk $PX_URL/portworx-etcd-dashboard.json)" > /dev/null 2>&1

# install with ingress
cat << EOF | kubectl apply -n portworx -f - > /dev/null 2>&1
apiVersion: v1
kind: Service
metadata:
  name: grafana
  labels:
    app: grafana
spec:
  type: ClusterIP
  ports:
    - port: 3000
  selector:
    app: grafana
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana
  labels:
    app: grafana
spec:
  replicas: 1
  selector:
    matchLabels:
      app: grafana
  template:
    metadata:
      labels:
        app: grafana
    spec:
      containers:
        - image: grafana/grafana
          name: grafana
          imagePullPolicy: IfNotPresent
          volumeMounts:
            - name: grafana-dash-config
              mountPath: /etc/grafana/provisioning/dashboards
            - name: dashboard-templates
              mountPath: /var/lib/grafana/dashboards
            - name: grafana-source-config
              mountPath: /etc/grafana/provisioning/datasources
      volumes:
        - name: grafana-source-config
          configMap:
            name: grafana-source-config
        - name: grafana-dash-config
          configMap:
            name: grafana-dashboard-config
        - name: dashboard-templates
          configMap:
            name: grafana-dashboards
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grafana
spec:
  rules:
  - host: grafana.rfed.io
    http:
      paths:
      - backend:
          service:
            name: grafana
            port:
              number: 3000
        path: /
        pathType: ImplementationSpecific
EOF

info_ok

info "navigate to - "$BLUE"https://central.rfed.io "$GREEN"admin / admin"$NO_COLOR""
info "navigate to - "$BLUE"https://grafana.rfed.io "$GREEN"admin / admin"$NO_COLOR""

}

################################ rancher ##############################
function rancher () {

  if [[ -z $(dolist | awk '{printf $3","}' | sed 's/,$//') ]] && ! kubectl get node > /dev/null 2>&1 ; then
    echo -e "$BLUE" "Building cluster first." "$NO_COLOR"
    up && longhorn
  fi

  echo -e "$BLUE" "deploying rancher" "$NO_COLOR"
  #helm repo add rancher-latest https://releases.rancher.com/server-charts/latest --force-update > /dev/null 2>&1
  #helm repo add jetstack https://charts.jetstack.io --force-update > /dev/null 2>&1

  echo -e -n " - helm - cert-manager"
  helm upgrade -i cert-manager jetstack/cert-manager -n cert-manager --create-namespace --set crds.enabled=true > /dev/null 2>&1 
  
  info_ok
  
  echo -e -n " - helm - rancher"

  # custom TLS certs
  kubectl create ns cattle-system > /dev/null 2>&1 
  # kubectl -n cattle-system create secret tls tls-rancher-ingress --cert=tls.crt --key=tls.key
  kubectl -n cattle-system create secret tls tls-rancher-ingress --cert=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.cert --key=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.key > /dev/null 2>&1 
  # kubectl -n cattle-system create secret generic tls-ca --from-file=cacerts.pem
  kubectl -n cattle-system create secret generic tls-ca --from-file=/Users/clemenko/Dropbox/work/rfed.me/io/cacerts.pem > /dev/null 2>&1 
  # kubectl -n cattle-system create secret generic tls-ca-additional --from-file=ca-additional.pem=cacerts.pem

  helm upgrade -i rancher rancher-latest/rancher -n cattle-system --create-namespace --set hostname=rancher.$domain --set bootstrapPassword=bootStrapAllTheThings --set replicas=1 --set auditLog.level=2 --set auditLog.destination=hostPath --set auditLog.hostPath=/var/log/rancher/audit --set auditLog.maxAge=30 --set antiAffinity=required --set antiAffinity=required  --set ingress.tls.source=secret --set ingress.tls.secretName=tls-rancher-ingress --set privateCA=true --set 'extraEnv[0].name=CATTLE_FEATURES' --set 'extraEnv[0].value=ui-sql-cache=true' > /dev/null 2>&1

  info_ok

  # wait for rancher
  echo -e -n " - waiting for rancher"
  until [ $(curl -sk https://rancher.$domain/v3-public/authproviders | grep local | wc -l ) = 1 ]; do 
    sleep 2; echo -e -n "."; done

  info_ok

  echo -e -n " - bootstrapping"
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

  info_ok

  # class banners
cat <<EOF | kubectl apply -f -  > /dev/null 2>&1
apiVersion: management.cattle.io/v3
kind: Setting
metadata:
  name: ui-banners
value: '{"bannerHeader":{"background":"#007a33","color":"#ffffff","textAlignment":"center","fontWeight":null,"fontStyle":null,"fontSize":"14px","textDecoration":null,"text":"UNCLASSIFIED//FOUO"},"bannerFooter":{"background":"#007a33","color":"#ffffff","textAlignment":"center","fontWeight":null,"fontStyle":null,"fontSize":"14px","textDecoration":null,"text":"UNCLASSIFIED//FOUO"},"bannerConsent":{"background":"#ffffff","color":"#000000","textAlignment":"left","fontWeight":null,"fontStyle":null,"fontSize":"14px","textDecoration":false,"text":"$govmessage","button":"Accept"},"showHeader":"true","showFooter":"true","showConsent":"true"}'
EOF

}

################################ longhorn ##############################
function longhorn () {
  echo -e -n  " - longhorn"
  # helm repo add longhorn https://charts.longhorn.io --force-update
  
  # to http basic auth --> https://longhorn.io/docs/1.4.1/deploy/accessing-the-ui/longhorn-ingress/

  helm upgrade -i longhorn  longhorn/longhorn -n longhorn-system --create-namespace --set ingress.enabled=true --set ingress.host=longhorn.$domain --set defaultSettings.storageMinimalAvailablePercentage=25 --set defaultSettings.storageOverProvisioningPercentage=200 --set defaultSettings.allowCollectingLonghornUsageMetrics=false --set persistence.defaultDataLocality="best-effort" > /dev/null 2>&1  #--set defaultSettings.v2DataEngine=true #--set defaultSettings.v1DataEngine=false  

  sleep 5

  #wait for longhorn to initiaize
  until [ $(kubectl get pod -n longhorn-system | grep -v 'Running\|NAME' | wc -l) = 0 ] && [ "$(kubectl get pod -n longhorn-system | wc -l)" -gt 19 ] ; do echo -e -n "." ; sleep 2; done
  # testing out ` kubectl wait --for condition=containersready -n longhorn-system pod --all`

  kubectl patch storageclass longhorn -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}' > /dev/null 2>&1
  if [ "$prefix" = k3s ]; then kubectl patch storageclass local-path -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"false"}}}' > /dev/null 2>&1; fi

  # add encryption per volume storage class 
  kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/longhorn_encryption.yml > /dev/null 2>&1

  info_ok
}

################################ neu ##############################
function neu () {
  echo -e -n  " - neuvector"
  
  # helm repo add neuvector https://neuvector.github.io/neuvector-helm/ --force-update
  
  # custom TLS certs
  kubectl create ns neuvector > /dev/null 2>&1 
  kubectl -n neuvector create secret tls tls-ingress --cert=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.cert --key=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.key > /dev/null 2>&1 

  kubectl -n neuvector create secret tls tls-fed-ingress --cert=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.cert --key=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.key > /dev/null 2>&1 

cat <<EOF | kubectl apply -f - > /dev/null 2>&1 
apiVersion: v1
kind: ConfigMap
metadata:
  name: neuvector-init
  namespace: neuvector
data:
  sysinitcfg.yaml: |
    always_reload: true
    Cluster_Name: neuvector.$domain
    No_Telemetry_Report: true
    Scan_Config:
      Auto_Scan: true
    Scanner_Autoscale:
      Min_Pods: 1
      Max_Pods: 3
  userinitcfg.yaml: |
    always_reload: true
    users:
    - Fullname: admin
      Password: $password
      Role: admin
      Timeout: 3600 
EOF

  export govmessage_html="PGI+WW91IGFyZSBhY2Nlc3NpbmcgYSBVLlMuIEdvdmVybm1lbnQgKFVTRykgSW5mb3JtYXRpb24gU3lzdGVtIChJUykgdGhhdCBpcyBwcm92aWRlZCBmb3IgVVNHLWF1dGhvcml6ZWQgdXNlIG9ubHkuPC9iPjxicj4KPGJyPgpCeSB1c2luZyB0aGlzIElTICh3aGljaCBpbmNsdWRlcyBhbnkgZGV2aWNlIGF0dGFjaGVkIHRvIHRoaXMgSVMpLCB5b3UgY29uc2VudCB0byB0aGUgZm9sbG93aW5nIGNvbmRpdGlvbnM6PGJyPgo8YnI+Ci1UaGUgVVNHIHJvdXRpbmVseSBpbnRlcmNlcHRzIGFuZCBtb25pdG9ycyBjb21tdW5pY2F0aW9ucyBvbiB0aGlzIElTIGZvciBwdXJwb3NlcyBpbmNsdWRpbmcsIGJ1dCBub3QgbGltaXRlZCB0bywgcGVuZXRyYXRpb24gdGVzdGluZywgQ09NU0VDIG1vbml0b3JpbmcsIG5ldHdvcmsgb3BlcmF0aW9ucyBhbmQgZGVmZW5zZSwgcGVyc29ubmVsIG1pc2NvbmR1Y3QgKFBNKSwgbGF3IGVuZm9yY2VtZW50IChMRSksIGFuZCBjb3VudGVyaW50ZWxsaWdlbmNlIChDSSkgaW52ZXN0aWdhdGlvbnMuPGJyPgo8YnI+Ci1BdCBhbnkgdGltZSwgdGhlIFVTRyBtYXkgaW5zcGVjdCBhbmQgc2VpemUgZGF0YSBzdG9yZWQgb24gdGhpcyBJUy48YnI+Cjxicj4KLUNvbW11bmljYXRpb25zIHVzaW5nLCBvciBkYXRhIHN0b3JlZCBvbiwgdGhpcyBJUyBhcmUgbm90IHByaXZhdGUsIGFyZSBzdWJqZWN0IHRvIHJvdXRpbmUgbW9uaXRvcmluZywgaW50ZXJjZXB0aW9uLCBhbmQgc2VhcmNoLCBhbmQgbWF5IGJlIGRpc2Nsb3NlZCBvciB1c2VkIGZvciBhbnkgVVNHLWF1dGhvcml6ZWQgcHVycG9zZS48YnI+Cjxicj4KLVRoaXMgSVMgaW5jbHVkZXMgc2VjdXJpdHkgbWVhc3VyZXMgKGUuZy4sIGF1dGhlbnRpY2F0aW9uIGFuZCBhY2Nlc3MgY29udHJvbHMpIHRvIHByb3RlY3QgVVNHIGludGVyZXN0cy0tbm90IGZvciB5b3VyIHBlcnNvbmFsIGJlbmVmaXQgb3IgcHJpdmFjeS48YnI+Cjxicj4KLU5vdHdpdGhzdGFuZGluZyB0aGUgYWJvdmUsIHVzaW5nIHRoaXMgSVMgZG9lcyBub3QgY29uc3RpdHV0ZSBjb25zZW50IHRvIFBNLCBMRSBvciBDSSBpbnZlc3RpZ2F0aXZlIHNlYXJjaGluZyBvciBtb25pdG9yaW5nIG9mIHRoZSBjb250ZW50IG9mIHByaXZpbGVnZWQgY29tbXVuaWNhdGlvbnMsIG9yIHdvcmsgcHJvZHVjdCwgcmVsYXRlZCB0byBwZXJzb25hbCByZXByZXNlbnRhdGlvbiBvciBzZXJ2aWNlcyBieSBhdHRvcm5leXMsIHBzeWNob3RoZXJhcGlzdHMsIG9yIGNsZXJneSwgYW5kIHRoZWlyIGFzc2lzdGFudHMuIFN1Y2ggY29tbXVuaWNhdGlvbnMgYW5kIHdvcmsgcHJvZHVjdCBhcmUgcHJpdmF0ZSBhbmQgY29uZmlkZW50aWFsLiBTZWUgVXNlciBBZ3JlZW1lbnQgZm9yIGRldGFpbHMuIDxicj4gCg=="

  # clear
  # helm upgrade -i neuvector -n neuvector neuvector/core --create-namespace --set k3s.enabled=true --set controller.pvc.enabled=true --set controller.pvc.capacity=500Mi --set internal.certmanager.enabled=true --set manager.ingress.enabled=true --set manager.ingress.host=neuvector.$domain --set manager.ingress.tls=true --set manager.ingress.secretName=tls-ingress --set controller.federation.mastersvc.ingress.enabled=true --set controller.federation.mastersvc.ingress.host=nv-api.rfed.io --set controller.federation.mastersvc.ingress.tls=true --set controller.federation.mastersvc.ingress.secretName=tls-ingress --set controller.federation.mastersvc.type=ClusterIP > /dev/null 2>&1

  # Unclass
  helm upgrade -i neuvector -n neuvector neuvector/core --create-namespace --set controller.pvc.enabled=true --set controller.pvc.capacity=500Mi --set manager.env.envs[0].name=CUSTOM_PAGE_HEADER_COLOR --set manager.env.envs[0].value="#007a33" --set manager.env.envs[1].name=CUSTOM_PAGE_HEADER_CONTENT --set manager.env.envs[1].value="VU5DTEFTU0lGSUVELy9GT1VPCg==" --set manager.env.envs[2].name=CUSTOM_PAGE_FOOTER_COLOR --set manager.env.envs[2].value="#007a33" --set manager.env.envs[3].name=CUSTOM_PAGE_FOOTER_CONTENT --set manager.env.envs[3].value="VU5DTEFTU0lGSUVELy9GT1VPCg==" --set manager.env.envs[4].name=CUSTOM_EULA_POLICY --set manager.env.envs[4].value=$govmessage_html --set manager.ingress.enabled=true --set manager.ingress.host=neuvector.$domain  --set manager.ingress.tls=true --set manager.ingress.secretName=tls-ingress  > /dev/null 2>&1

  # federation 
  # --set controller.federation.mastersvc.ingress.enabled=true --set controller.federation.mastersvc.ingress.host=nv-api.rfed.io --set controller.federation.mastersvc.ingress.tls=true --set controller.federation.mastersvc.ingress.secretName=tls-fed-ingress --set controller.federation.mastersvc.type=ClusterIP 

  # TS
  # helm upgrade -i neuvector -n neuvector neuvector/core --create-namespace --set k3s.enabled=true --set controller.pvc.enabled=true --set controller.pvc.capacity=500Mi --set internal.certmanager.enabled=true --set manager.env.envs[0].name=CUSTOM_PAGE_HEADER_COLOR --set manager.env.envs[0].value="#fce83a" --set manager.env.envs[1].name=CUSTOM_PAGE_HEADER_CONTENT --set manager.env.envs[1].value="VE9QIFNFQ1JFVC8vU0NJCg==" --set manager.env.envs[2].name=CUSTOM_PAGE_FOOTER_COLOR --set manager.env.envs[2].value="#fce83a" --set manager.env.envs[3].name=CUSTOM_PAGE_FOOTER_CONTENT --set manager.env.envs[3].value="VE9QIFNFQ1JFVC8vU0NJCg==" --set manager.env.envs[4].name=CUSTOM_EULA_POLICY --set manager.env.envs[4].value=$govmessage_html --set manager.ingress.enabled=true --set manager.ingress.host=neuvector.$domain --set manager.ingress.secretName=tls-ingress --set controller.federation.mastersvc.ingress.enabled=true --set controller.federation.mastersvc.ingress.host=nv-api.rfed.io --set controller.federation.mastersvc.ingress.tls=true --set controller.federation.mastersvc.ingress.secretName=tls-ingress --set controller.federation.mastersvc.type=ClusterIP > /dev/null 2>&1

  until [[ "$(curl -skL -H "Content-Type: application/json" -o /dev/null -w '%{http_code}' https://neuvector.$domain/auth -d '{"isRancherSSOUrl":false, "username": "admin", "password": "'$password'"}')" == "200" ]]; do echo -e -n .; sleep 1; done

  TOKEN=$(curl -sk -H "Content-Type: application/json" https://neuvector.$domain/auth -d '{"isRancherSSOUrl":false, "username": "admin", "password": "'$password'"}' | jq  -r .token.token)

  curl -sk -H "Content-Type: application/json" -H 'Token: '$TOKEN https://neuvector.$domain/eula -d '{"accepted":true}' > /dev/null 2>&1

  info_ok

 # federation managed
 # helm upgrade -i neuvector -n neuvector neuvector/core --create-namespace --set k3s.enabled=true --set manager.ingress.enabled=true --set manager.ingress.host=neuvector2.rfed.io --set manager.ingress.tls=true --set manager.ingress.secretName=tls-ingress --set controller.federation.managedsvc.ingress.enabled=true --set controller.federation.managedsvc.ingress.host=nv-down1.rfed.io --set controller.federation.managedsvc.ingress.tls=true --set controller.federation.managedsvc.ingress.secretName=tls-ingress --set controller.federation.managedsvc.type=ClusterIP

 # https://gist.github.com/clemenko/385d6ce697e1f7a4601dbfc24d9a87e2
}

############################# fleet ################################
function fleet () {
  echo -e -n " fleet-ing"
  # for downstream clusters
  # kubectl create secret -n cattle-global-data generic awscred --from-literal=amazonec2credentialConfig-defaultRegion=us-east-1 --from-literal=amazonec2credentialConfig-accessKey=${AWS_ACCESS_KEY} --from-literal=amazonec2credentialConfig-secretKey=${AWS_SECRET_KEY}  > /dev/null 2>&1

  kubectl create secret -n cattle-global-data generic docreds --from-literal=digitaloceancredentialConfig-accessToken=${DO_TOKEN} > /dev/null 2>&1

  kubectl apply -f https://raw.githubusercontent.com/clemenko/fleet/main/gitrepo.yml > /dev/null 2>&1
  
  info_ok
}

############################# demo ################################
function demo () {
  echo -e " demo-ing"

  # echo -e -n " - whoami ";kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/whoami.yml > /dev/null 2>&1; info_ok

  echo -e -n " - flask ";kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/master/flask_simple_nginx.yml > /dev/null 2>&1; info_ok
  
  # echo -e -n " - ghost ";kubectl apply -f https://raw.githubusercontent.com/clemenko/k8s_yaml/refs/heads/master/ghost.yaml > /dev/null 2>&1; info_ok
  
  echo -e -n " - minio"
  helm repo add minio https://charts.min.io/ --force-update
  #kubectl create ns minio > /dev/null 2>&1 
  # kubectl -n minio create secret tls tls-ingress --cert=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.cert --key=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.key > /dev/null 2>&1 

  helm upgrade -i minio minio/minio -n minio --set rootUser=admin,rootPassword=$password --create-namespace --set mode=standalone --set resources.requests.memory=1Gi --set persistence.size=10Gi --set mode=standalone --set ingress.enabled=true --set ingress.hosts[0]=s3.$domain --set consoleIngress.enabled=true --set consoleIngress.hosts[0]=minio.$domain --set ingress.annotations."nginx\.ingress\.kubernetes\.io/proxy-body-size"="1024m" --set consoleIngress.annotations."nginx\.ingress\.kubernetes\.io/proxy-body-size"="1024m" > /dev/null 2>&1
  info_ok

   # --set consoleIngress.tls[0].secretName=tls-ingress --set ingress.tls[0].secretName=tls-ingress 

#  echo -e -n " - gitness"
#  curl -s https://raw.githubusercontent.com/clemenko/k8s_yaml/master/gitness.yaml  | sed "s/rfed.xx/$domain/g" | kubectl apply -f - > /dev/null 2>&1
#  info_ok

#  echo -e -n " - harbor"
  # helm repo add harbor https://helm.goharbor.io --force-update
#  kubectl create ns harbor > /dev/null 2>&1 
#  kubectl -n harbor create secret tls tls-ingress --cert=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.cert --key=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.key > /dev/null 2>&1 

#  helm upgrade -i harbor harbor/harbor -n harbor --create-namespace --set expose.tls.certSource=secret --set expose.tls.secret.secretName=tls-ingress --set expose.tls.enabled=false --set expose.tls.auto.commonName=harbor.$domain --set expose.ingress.hosts.core=harbor.$domain --set persistence.enabled=false --set harborAdminPassword=$password --set externalURL=http://harbor.$domain --set notary.enabled=false > /dev/null 2>&1;
#  info_ok

  echo -e -n " - gitea"
  helm upgrade -i gitea oci://registry-1.docker.io/giteacharts/gitea -n gitea --create-namespace --set gitea.admin.password=$password --set gitea.admin.username=gitea --set persistence.size=500Mi --set ingress.enabled=true --set ingress.hosts[0].host=git.$domain --set ingress.hosts[0].paths[0].path=/ --set ingress.hosts[0].paths[0].pathType=Prefix --set gitea.config.server.DOMAIN=git.$domain --set postgresql-ha.enabled=false --set redis-cluster.enabled=false --set gitea.config.database.DB_TYPE=sqlite3 --set gitea.config.session.PROVIDER=memory  --set gitea.config.cache.ADAPTER=memory --set gitea.config.queue.TYPE=level > /dev/null 2>&1

  # mirror github
  until [ $(curl -s http://git.$domain/explore/repos| grep "<title>" | wc -l) = 1 ]; do sleep 2; echo -n "."; done

  sleep 5
  
  curl -X POST http://git.$domain/api/v1/repos/migrate -H 'accept: application/json' -H 'authorization: Basic Z2l0ZWE6UGEyMndvcmQ=' -H 'Content-Type: application/json' -d '{ "clone_addr": "https://github.com/clemenko/fleet", "repo_name": "fleet","repo_owner": "gitea"}' > /dev/null 2>&1
  info_ok

#  echo -e -n " - tailscale "
#  curl -s https://raw.githubusercontent.com/clemenko/k8s_yaml/master/tailscale.yaml  | sed -e "s/XXX/$TAILSCALE_ID/g" -e "s/ZZZ/$TAILSCALE_TOKEN/g" | kubectl apply -f - > /dev/null 2>&1
#  info_ok
} 

################################ keycloak ##############################
# helm repo add bitnami https://charts.bitnami.com/bitnami --force-update

function keycloak () {
  
  KEY_URL=keycloak.$domain
  RANCHER_URL=rancher.$domain

  echo -e " keycloaking"
  echo -e -n " - deploying"
  
  kubectl create ns keycloak > /dev/null 2>&1 
  kubectl -n keycloak create secret tls tls-ingress --cert=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.cert --key=/Users/clemenko/Dropbox/work/rfed.me/io/star.rfed.io.key > /dev/null 2>&1 
  # kubectl -n keycloak create secret generic tls-ca --from-file=/Users/clemenko/Dropbox/work/rfed.me/io/cacerts.pem > /dev/null 2>&1 

  curl -s https://raw.githubusercontent.com/clemenko/k8s_yaml/master/keycloak.yml  | sed "s/rfed.xx/$domain/g" | kubectl apply -f - > /dev/null 2>&1

  #helm upgrade -i keycloak  bitnami/keycloak --namespace keycloak --create-namespace --set auth.adminUser=admin --set auth.adminPassword=Pa22word > /dev/null 2>&1
  # --set ingress.enabled=true --set ingress.hostname=keycloak.$domain --set ingress.tls=true --set tls.enabled=true --set httpRelativePath="/"
  
  info_ok
  
  echo -e -n " - waiting for keycloak"

  until [ $(curl -sk https://$KEY_URL/ | grep "Administration Console" | wc -l) = 1 ]; do echo -e -n "." ; sleep 2; done
  info_ok

  echo -e -n " - adding realm and client"

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

  # add realm-managementview-users	
  # get role id
  # role_ID=$(curl -sk -X GET https://$KEY_URL/admin/realms/rancher/roles -H "authorization: Bearer $key_token" | jq -r '.[]  | select(.name=="default-roles-rancher") | .id')
  
  # curl -sk https://$KEY_URL/admin/realms/rancher/roles-by-id/$role_ID/composites -H "authorization: Bearer $key_token"  -d '[{"id":"d8ef39c5-c8b6-4bcc-8010-7244b7e5cf4a","name":"view-users","description":"${role_view-users}"}]'

  # add groups admin / dev
  curl -k https://$KEY_URL/admin/realms/rancher/groups -H 'Content-Type: application/json' -H "authorization: Bearer $key_token" -d '{"name":"devs"}'
 
  curl -k https://$KEY_URL/admin/realms/rancher/groups -H 'Content-Type: application/json' -H "authorization: Bearer $key_token" -d '{"name":"admins"}'

 
  # add keycloak user clemenko / Pa22word
  curl -k 'https://'$KEY_URL'/admin/realms/rancher/users' -H 'Content-Type: application/json' -H "authorization: Bearer $key_token" -d '{"enabled":true,"attributes":{},"groups":["/devs"],"credentials":[{"type":"password","value":"'$password'","temporary":false}],"username":"clemenko","emailVerified":"","firstName":"Andy","lastName":"Clemenko"}' 

  # add keycloak user admin / Pa22word
  curl -k 'https://'$KEY_URL'/admin/realms/rancher/users' -H 'Content-Type: application/json' -H "authorization: Bearer $key_token" -d '{"enabled":true,"attributes":{},"groups":["/admins", "/devs"],"credentials":[{"type":"password","value":"'$password'","temporary":false}],"username":"admin","emailVerified":"","firstName":"Admin","lastName":"Clemenko"}' 

  info_ok

  echo -e -n " - configuring rancher"
  # configure rancher
  token=$(curl -sk -X POST https://$RANCHER_URL/v3-public/localProviders/local?action=login -H 'content-type: application/json' -d '{"username":"admin","password":"'$password'"}' | jq -r .token)

  api_token=$(curl -sk https://$RANCHER_URL/v3/token -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"type":"token","description":"automation"}' | jq -r .token)

  curl -sk -X PUT https://$RANCHER_URL/v3/keyCloakOIDCConfigs/keycloakoidc?action=testAndEnable -H 'accept: application/json' -H 'accept-language: en-US,en;q=0.9' -H 'content-type: application/json;charset=UTF-8' -H 'content-type: application/json' -H "Authorization: Bearer $api_token" -X PUT -d '{"enabled":true,"id":"keycloakoidc","name":"keycloakoidc","type":"keyCloakOIDCConfig","accessMode":"unrestricted","rancherUrl":"https://rancher.'$domain'/verify-auth","scope":"openid profile email","clientId":"rancher","clientSecret":"'$client_secret'","issuer":"https://keycloak.'$domain'/realms/rancher","authEndpoint":"https://'$KEY_URL'/realms/rancher/protocol/openid-connect/auth/"}' > /dev/null 2>&1

  # login with keycloak user - manual

  info_ok

}

################################ stackrox ##############################
function rox () {
# https://github.com/stackrox/stackrox#quick-installation-using-helm
# helm repo add stackrox https://raw.githubusercontent.com/stackrox/helm-charts/main/opensource/ --force-update

echo -e -n  " - stackrox"

 helm upgrade -i stackrox-central-services stackrox/stackrox-central-services -n stackrox --create-namespace --set central.adminPassword.value=$password --set central.resources.requests.memory=1Gi --set central.resources.limits.memory=2Gi --set central.db.resources.requests.memory=1Gi --set central.db.resources.limits.memory=2Gi --set scanner.autoscaling.disable=true --set scanner.replicas=1 --set scanner.resources.requests.memory=500Mi --set scanner.resources.limits.memory=2500Mi --set central.resources.requests.cpu=1 --set central.resources.limits.cpu=1 --set central.db.resources.requests.cpu=500m --set central.db.resources.limits.cpu=1 --set central.persistence.none=true --set central.db.persistence.persistentVolumeClaim.size=1Gi > /dev/null 2>&1

#--set central.exposure.loadBalancer.enabled=true

 until [ $(kubectl get pod -n stackrox |grep Running| wc -l) = 4 ] ; do echo -e -n "." ; sleep 2; done

cat <<EOF | kubectl apply -f - > /dev/null 2>&1
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: stackrox
  namespace: stackrox
  annotations:
    nginx.ingress.kubernetes.io/ssl-passthrough: "true"
spec:
  rules:
  - host: stackrox.$domain
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: central
            port:
              number: 443
EOF
 sleep 5

 export ROX_API_TOKEN=$(curl -sk -X POST -u admin:$password https://stackrox.$domain/v1/apitokens/generate -d '{"name":"admin","role":null,"roles":["Admin"]}'| jq -r .token)

 curl -ks https://stackrox.$domain/v1/cluster-init/init-bundles -H 'accept: application/json, text/plain, */*' -H "authorization: Bearer $ROX_API_TOKEN" -H 'content-type: application/json' -d '{"name":"rke2"}' |jq -r .helmValuesBundle | base64 -D > stackrox-init-bundle.yaml

 helm upgrade --install --create-namespace -n stackrox stackrox-secured-cluster-services stackrox/stackrox-secured-cluster-services -f stackrox-init-bundle.yaml --set clusterName=rke2 --set centralEndpoint="central.stackrox.svc:443" --set sensor.resources.requests.memory=500Mi --set sensor.resources.requests.cpu=500m --set sensor.resources.limits.memory=500Mi --set sensor.resources.limits.cpu=500m > /dev/null 2>&1

 rm -rf stackrox-init-bundle.yaml 

 info_ok
}


# PSA notes
# kubectl label ns spark pod-security.kubernetes.io/audit=privileged pod-security.kubernetes.io/enforce=privileged pod-security.kubernetes.io/warn=privileged