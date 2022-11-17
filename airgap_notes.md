# air gap notes

### get the script

script: https://github.com/clemenko/rke_airgap_install/blob/main/air_gap_all_the_things.sh

```bash
mkdir /opt/rancher && cd /opt/rancher && curl -#OL https://raw.githubusercontent.com/clemenko/rke_airgap_install/main/air_gap_all_the_things.sh && chmod 755 air_gap_all_the_things.sh 
```

### uncompress

```bash
tar -I zstd -vxf rke2_rancher_longhorn.zst -C /opt/rancher
```

### Longhorn

docs : https://longhorn.io/docs/1.3.2/advanced-resources/deploy/airgap/#using-a-helm-chart

```bash
# weird bug i need to fix
skopeo copy docker-archive:/opt/rancher/images/longhorn/longhorn-instance-manager_v1_20221003.tar docker://localhost:5000/longhornio/longhorn-instance-manager:v1_20221003 --dest-tls-verify=false
```

```bash
helm install longhorn /opt/rancher/helm/longhorn-1.3.2.tgz --namespace longhorn-system --create-namespace --set ingress.enabled=true --set ingress.host=longhorn.awesome.sauce --set global.cattle.systemDefaultRegistry=localhost:5000
```

### Cert-Manager

```bash
helm install cert-manager /opt/rancher/helm/cert-manager-v1.10.0.tgz --namespace cert-manager --create-namespace --set installCRDs=true --set image.repository=localhost:5000/cert-manager-controller --set webhook.image.repository=localhost:5000/cert-manager-webhook --set cainjector.image.repository=localhost:5000/cert-manager-cainjector --set startupapicheck.image.repository=localhost:5000/cert-manager-ctl
```

### Rancher

docs : https://docs.ranchermanager.rancher.io/pages-for-subheaders/air-gapped-helm-cli-install

```bash
helm install rancher /opt/rancher/helm/rancher-2.7.0.tgz --namespace cattle-system --create-namespace --set hostname=rancher.awesome.sauce --set bootstrapPassword=bootStrapAllTheThings --set replicas=1 --set auditLog.level=2 --set auditLog.destination=hostPath --set useBundledSystemChart=true --set rancherImage=localhost:5000/rancher/rancher --set systemDefaultRegistry=localhost:5000 --set certmanager.version=v1.10.0

#  --no-hooks --set rancherImageTag=v2.7.0
```
