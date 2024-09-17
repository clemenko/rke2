# STIG's tl:dr

Simply go to https://public.cyber.mil/stigs/downloads/ and search for `rancher`.  

Direct Downloads

- https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RGS_MCM_V1R3_STIG.zip
- https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RGS_RKE2_V1R5_STIG.zip
- https://public.cyber.mil/stigs/srg-stig-tools/

## RKE2 STIG tl:dr

### config.yaml

`/etc/rancher/rke2/config.yaml`

```yaml
profile: cis # for 1.28 and older cis-1.23
selinux: true
secrets-encryption: true
token: bootstrapAllTheThings
tls-san:
- rke.rfed.io
write-kubeconfig-mode: 0600
use-service-account-credentials: true
pod-security-admission-config-file: /etc/rancher/rke2/rancher-psact.yaml
kube-controller-manager-arg:
- bind-address=127.0.0.1
- use-service-account-credentials=true
- tls-min-version=VersionTLS12
- tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
kube-scheduler-arg:
- tls-min-version=VersionTLS12
- tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
kube-apiserver-arg:
- tls-min-version=VersionTLS12
- tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- authorization-mode=RBAC,Node
- anonymous-auth=false
- audit-policy-file=/etc/rancher/rke2/audit-policy.yaml
- audit-log-mode=blocking-strict
- audit-log-maxage=30
- audit-log-path=/var/lib/rancher/rke2/server/logs/audit.log
kubelet-arg:
- kube-reserved=cpu=400m,memory=1Gi
- system-reserved=cpu=400m,memory=1Gi
- protect-kernel-defaults=true
- read-only-port=0
- authorization-mode=Webhook
- streaming-connection-idle-timeout=5m
- max-pods=400
```

### Audit Policy

`/etc/rancher/rke2/audit-policy.yaml`
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
metadata:
  name: rke2-audit-policy
rules:
  - level: Metadata
    resources:
    - group: ""
      resources: ["secrets"]
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["*"]
```

### PSA

Keep in mind that the namespace can be labeled for the correct PSP after it is created.

`kubectl label ns $NAMESPACE pod-security.kubernetes.io/audit=privileged pod-security.kubernetes.io/enforce=privileged pod-security.kubernetes.io/warn=privileged`

OR add it to `/etc/rancher/rke2/rancher-psact.yaml`.

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
  - name: PodSecurity
    configuration:
      apiVersion: pod-security.admission.config.k8s.io/v1
      kind: PodSecurityConfiguration
      defaults:
        enforce: "restricted"
        enforce-version: "latest"
        audit: "restricted"
        audit-version: "latest"
        warn: "restricted"
        warn-version: "latest"
      exemptions:
        usernames: []
        runtimeClasses: []
        namespaces: [calico-apiserver,
                     calico-system,
                     carbide-docs-system,
                     carbide-stigatron-system,
                     cattle-alerting,
                     cattle-csp-adapter-system,
                     cattle-elemental-system,
                     cattle-epinio-system,
                     cattle-externalip-system,
                     cattle-fleet-local-system,
                     cattle-fleet-system,
                     cattle-gatekeeper-system,
                     cattle-global-data,
                     cattle-global-nt,
                     cattle-impersonation-system,
                     cattle-istio,
                     cattle-istio-system,
                     cattle-logging,
                     cattle-logging-system,
                     cattle-monitoring-system,
                     cattle-neuvector-system,
                     cattle-prometheus,
                     cattle-provisioning-capi-system,
                     cattle-resources-system,
                     cattle-sriov-system,
                     cattle-system,
                     cattle-ui-plugin-system,
                     cattle-windows-gmsa-system,
                     cert-manager,
                     cis-operator-system,
                     fleet-default,
                     fleet-local,
                     ingress-nginx,
                     istio-system,
                     kube-node-lease,
                     kube-public,
                     kube-system,
                     longhorn-system,
                     rancher-alerting-drivers,
                     security-scan,
                     tigera-operator,
                     neuvector,
                     flask,
                     ghost,
                     kubecon,
                     minio,
                     whoami,
                     harbor,
                     gitea,
                     tailscale,
                     gitness,
                     stackrox,
                     keycloak]
```

## Rancher STIG tl:dr

From
- https://ranchermanager.docs.rancher.com/v2.8/how-to-guides/advanced-user-guides/enable-api-audit-log
- https://ranchermanager.docs.rancher.com/getting-started/installation-and-upgrade/installation-references/helm-chart-options#advanced-options

```bash
helm upgrade -i rancher rancher-latest/rancher -n cattle-system --create-namespace --set hostname=rancher.$domain --set bootstrapPassword=bootStrapAllTheThings --set auditLog.level=2 --set auditLog.destination=hostPath --set auditLog.hostPath=/var/log/rancher/audit --set auditLog.maxAge=30 --set antiAffinity=required