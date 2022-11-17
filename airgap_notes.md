


Longhorn:

https://longhorn.io/docs/1.3.2/advanced-resources/deploy/airgap/#using-a-helm-chart

helm install longhorn /opt/rancher/helm/longhorn-1.3.2.tgz --namespace longhorn-system --create-namespace --set ingress.enabled=true --set ingress.host=longhorn.awesome.sauce --set global.cattle.systemDefaultRegistry=localhost:5000


Cert-Manager:

helm install cert-manager /opt/rancher/helm/cert-manager-v1.10.0.tgz --namespace cert-manager --create-namespace --set installCRDs=true --set image.repository=localhost:5000/cert-manager-controller --set webhook.image.repository=localhost:5000/cert-manager-webhook --set cainjector.image.repository=localhost:5000/cert-manager-cainjector --set startupapicheck.image.repository=localhost:5000/cert-manager-ctl


Rancher: 

https://docs.ranchermanager.rancher.io/pages-for-subheaders/air-gapped-helm-cli-install


   helm install rancher ./rancher-<VERSION>.tgz \
    --namespace cattle-system \
    --set hostname=<RANCHER.YOURDOMAIN.COM> \
    --set certmanager.version=<CERTMANAGER_VERSION> \
    --set rancherImage=<REGISTRY.YOURDOMAIN.COM:PORT>/rancher/rancher \
    --set systemDefaultRegistry=<REGISTRY.YOURDOMAIN.COM:PORT> \ # Set a default private registry to be used in Rancher
    --set useBundledSystemChart=true # Use the packaged Rancher system charts



  helm install rancher /opt/rancher/helm/rancher-2.7.0.tgz --namespace cattle-system --create-namespace --set hostname=rancher.$domain --set bootstrapPassword=bootStrapAllTheThings --set replicas=1 --set auditLog.level=2 --set auditLog.destination=hostPath --set useBundledSystemChart=true --set systemDefaultRegistry=localhost:5000

  