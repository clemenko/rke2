# RKE2 STIG tl;dr

Just a simple guide for navigating the RKE2 STIG from DISA. There is a nice article about it from [Businesswire](https://www.businesswire.com/news/home/20221101005546/en/DISA-Validates-Rancher-Government-Solutions%E2%80%99-Kubernetes-Distribution-RKE2-Security-Technical-Implementation-Guide).

You can download the STIG itself from [https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RGS_RKE2_V1R1_STIG.zip](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RGS_RKE2_V1R1_STIG.zip). The SITG viewer can be found on DISA's site at [https://public.cyber.mil/stigs/srg-stig-tools/](https://public.cyber.mil/stigs/srg-stig-tools/). For this guide I have simplified the controls and provided simple steps to ensure compliance. Hope this helps a little.

At the bottom is a complete `/etc/rancher/rke2/config.yaml` for all the controls.

## V-254553 - Strong TLS

The control is for using strong TLS settings. Aka Minimum TLS version and Ciphers. Below is the section that needs to be added to the Control Plane Nodes `/etc/rancher/rke2/config.yaml`.

Fix Text:

"Use strong TLS settings.

Edit the RKE2 Server configuration file on all RKE2 Server hosts, located at /etc/rancher/rke2/config.yaml, to contain the following:

kube-controller-manager-arg: 
- "tls-min-version=VersionTLS12" [or higher]
- "tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
kube-scheduler-arg: 
- "tls-min-version=VersionTLS12"
- "tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
kube-apiserver-arg: 
- "tls-min-version=VersionTLS12"
- "tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server"

## V-254554 - Centralized User Management

The Kubernetes Controller Manager is a background process that embeds core control loops regulating cluster system state through the API Server. Every process executed in a pod has an associated service account. By default, service accounts use the same credentials for authentication. Implementing the default settings poses a high risk to the Kubernetes Controller Manager. Setting the use-service-account-credential value lowers the attack surface by generating unique service accounts settings for each controller instance.

```bash
kube-controller-manager-arg:
- "use-service-account-credentials=true"
```

## V-254555 - Audit Logging

Rancher RKE2 components must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including SRGs, STIGs, NSA configuration guides, CTOs, and DTMs.

Fix Text:

Edit the /etc./rancher/rke2/config.yaml file, and enable the audit policy:
audit-policy-file: /etc./rancher/rke2/audit-policy.yaml

1. Edit the RKE2 Server configuration file on all RKE2 Server hosts, located at /etc./rancher/rke2/config.yaml, so that it contains required configuration. 

--audit-policy-file= Path to the file that defines the audit policy configuration. (Example: /etc./rancher/rke2/audit-policy.yaml)
--audit-log-mode=blocking-strict

If configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server

2. Edit the RKE2 Server configuration file on all RKE2 Server hosts, located at /etc./rancher/rke2/config.yaml, so that it contains required configuration. For example:

profile: cis-1.6

If configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server

3. Edit the audit policy file, by default located at /etc./rancher/rke2/audit-policy.yaml to look like below:

# Log all requests at the RequestResponse level.
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse

If configuration files are updated on a host, restart the RKE2 Service. Run the command:
'systemctl restart rke2-server' for server hosts and
'systemctl restart rke2-agent' for agent hosts.

## V-254556 - KubeController Bind Address

The Kubernetes Controller Manager must have secure binding.

Fix Text:

"Edit the Controller Manager pod specification file /var/lib/rancher/rke2/agent/pod-manifests/kube-controller-manager.yaml on the RKE2 Control Plane to set the below parameter:
--bind-address argument=127.0.0.1

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server"

## V-254557 - Kubelet No Anonymous Auth

The Kubernetes Kubelet must have anonymous authentication disabled.

Fix Text:

"Edit the Kubernetes Kubelet file etc/rancher/rke2/config.yaml on the RKE2 Control Plane and set the following:
--anonymous-auth=false

Once configuration file is updated, restart the RKE2 Agent. Run the command:
systemctl restart rke2-agent"

## V-254558 - KubeAPI Insecure Port

The Kubernetes API server must have the insecure port flag disabled. Deprecated in 1.10. Any version higher can ignore this control.

Fix Text:

"Edit the /var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml file
--insecure-port=0

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server"

## V-254559 - Kubelet Read-Only

The Kubernetes Kubelet must have the read-only port flag disabled.

Fix Text:

"Edit the Kubernetes Kubelet file etc/rancher/rke2/config.yaml on the RKE2 Control Plane and set the following:
--read-only-port=0

Once configuration file is updated, restart the RKE2 Agent. Run the command:
systemctl restart rke2-agent"

## V-254560 - KubeAPI Bind Address

The Kubernetes API server must have the insecure bind address not set.

Fix Text:

"Edit the /var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml on the Kubernetes RKE2 Control Plane.

Remove the value for the --insecure-bind-address setting.

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server"

## V-254561 - Kubelet Explicit Auth

The Kubernetes kubelet must enable explicit authorization.

Fix Text:

"Edit the Kubernetes Kubelet file etc/rancher/rke2/config.yaml on the RKE2 Control Plane and set the following:

--authorization-mode=Webhook

Once configuration file is updated, restart the RKE2 Agent. Run the command:
systemctl restart rke2-agent"

## V-254562 - KubeAPI Auth Disabled

The Kubernetes API server must have anonymous authentication disabled.

Fix Text:

"Edit the /var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml file

--anonymous-auth=false

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server"

## V-254563 - KubeAPI Audit Logs

All audit records must identify any containers associated with the event within Rancher RKE2.

Fix Text:

"Edit the /var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml file

--audit-log-maxage=30

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server"

## V-254564 - File Permissions

Configuration and authentication files for Rancher RKE2 must be protected.

Fix Text:

"File system permissions:
1. Fix permissions of the files in /etc/rancher/rke2
cd /etc/rancher/rke2
chmod 0640 ./*
chown root:root ./*
ls -l

2. Fix permissions of the files in /var/lib/rancher/rke2
cd /var/lib/rancher/rke2
chown root:root ./*
ls -l 

3. Fix permissions of the files and directories in /var/lib/rancher/rke2/agent
cd /var/lib/rancher/rke2/agent
chown root:root ./*
chmod 0700 pod-manifests
chmod 0700 etc
find . -maxdepth 1 -type f -name "*.kubeconfig" -exec chmod 0640 {} \;
find . -maxdepth 1 -type f -name "*.crt" -exec chmod 0600 {} \;
find . -maxdepth 1 -type f -name "*.key" -exec chmod 0600 {} \;
ls -l

4. Fix permissions of the files in /var/lib/rancher/rke2/bin
cd /var/lib/rancher/rke2/agent/bin
chown root:root ./*
chmod 0750 ./*
ls -l

5. Fix permissions of files in /var/lib/rancher/rke2/data
cd /var/lib/rancher/rke2/data
chown root:root ./*
chmod 0640 ./*
ls -l

6. Fix permissions in /var/lib/rancher/rke2/server
cd /var/lib/rancher/rke2/server
chown root:root ./*
chmod 0700 cred
chmod 0700 db
chmod 0700 tls
chmod 0750 manifests
chmod 0750 logs
chmod 0600 token
ls -l

Edit the RKE2 Server configuration file on all RKE2 Server hosts, located at /etc/rancher/rke2/config.yaml, to contain the following:

write-kubeconfig-mode: "0640"

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server"

## V-254565 - Disable Unnecessary Components

Rancher RKE2 must be configured with only essential configurations.

Fix Text:

"Disable unnecessary RKE2 components.
Edit the RKE2 Server configuration file on all RKE2 Server hosts, located at /etc/rancher/rke2/config.yaml, so that it contains a "disable" flag for all unnecessary components.

Example:
disable: rke2-canal
disable: rke2-coredns
disable: rke2-ingress-nginx
disable: rke2-kube-proxy
disable: rke2-metrics-server

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server"

## V-254566 - Enforce Ports and Protocols

Rancher RKE2 runtime must enforce ports, protocols, and services that adhere to the PPSM CAL.

Fix Text:

"Review the documentation covering how to set these PPSs and update this configuration file:

 /etc/rancher/rke2/config.yaml

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server"

## V-254567 - Store Cryptographic Passwords

Rancher RKE2 must store only cryptographic representations of passwords.

Fix Text:

Any secrets stored as environment variables must be moved to the secret files with the proper protections and enforcements or placed within a password vault.

## V-254568 - Session Termination

Rancher RKE2 must terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after five minutes of inactivity.

Fix Text:

"Edit the Kubernetes Kubelet file etc/rancher/rke2/config.yaml on the RKE2 Control Plane and set the following:
--streaming-connection-idle-timeout=5m

Once configuration file is updated, restart the RKE2 Agent. Run the command:
systemctl restart rke2-agent"

## V-254569 - Kubelet Isolate Security Functions

Rancher RKE2 runtime must isolate security functions from nonsecurity functions.

Fix Text:

"Edit the Kubernetes Kubelet file etc/rancher/rke2/config.yaml on the RKE2 Control Plane and set the following:
 --protect-kernel-defaults=true

Once configuration file is updated, restart the RKE2 Agent. Run the command:
systemctl restart rke2-agent"

## V-254570 - Maintain Namespace Isolation

Rancher RKE2 runtime must maintain separate execution domains for each container by assigning each container a separate address space to prevent unauthorized and unintended information transfer via shared system resources.

Fix Text:

"System namespaces are reserved and isolated.

A resource cannot move to a new namespace; the resource must be deleted and recreated in the new namespace.

kubectl delete <resource_type> <resource_name>
kubectl create -f <resource.yaml> --namespace=<user_created_namespace>"

## V-254571 - Prevent Nonprivileged Users

Rancher RKE2 must prevent nonprivileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

Fix Text:

"From the Server node, save the following policy to a file called restricted.yml.
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: 'docker/default,runtime/default'
    apparmor.security.beta.kubernetes.io/allowedProfileNames: 'runtime/default'
    seccomp.security.alpha.kubernetes.io/defaultProfileName:  'runtime/default'
    apparmor.security.beta.kubernetes.io/defaultProfileName:  'runtime/default'
spec:
  privileged: false
  # Required to prevent escalations to root.
  allowPrivilegeEscalation: false
  # This is redundant with non-root + disallow privilege escalation,
  # but we can provide it for defense in depth.
  requiredDropCapabilities:
    - ALL
  # Allow core volume types.
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    # Assume that persistentVolumes set up by the cluster admin are safe to use.
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    # Require the container to run without root privileges.
    rule: 'MustRunAsNonRoot'
  seLinux:
    # This policy assumes the nodes are using AppArmor rather than SELinux.
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
      # Forbid adding the root group.
      - min: 1
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      # Forbid adding the root group.
      - min: 1
        max: 65535
  readOnlyRootFilesystem: false

To implement the policy, run the command:

kubectl create -f restricted.yml"

## V-254572 - Control Access to API

Rancher RKE2 must prohibit the installation of patches, updates, and instantiation of container images without explicit privileged status.

Fix Text:

"Edit the /var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml file.
--authorization-mode=RBAC,Node

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server"

## V-254573 - Secrets Encryption

Rancher RKE2 keystore must implement encryption to prevent unauthorized disclosure of information at rest within Rancher RKE2.

Fix Text:

"Enable secrets encryption.

Edit the RKE2 configuration file on all RKE2 servers, located at /etc/rancher/rke2/config.yaml, so that it does NOT contain:

secrets-encryption: false

or that secrets-encryption is set to true."

## V-254574 - Remove Old Components

Rancher RKE2 must remove old components after updated versions have been installed.

Fix Text:

"Remove any old pods that are using older images. On the RKE2 Control Plane, run the command:

kubectl delete pod podname
(Note: "podname" is the name of the pod to delete.)

Run the command:
systemctl restart rke2-server"

## V-254575 - Updated Registry

Rancher RKE2 registry must contain the latest images with most recent updates and execute within Rancher RKE2 runtime as authorized by IAVM, CTOs, DTMs, and STIGs.

Fix Text:

Upgrade RKE2 to the supported version. Institute and adhere to the policies and procedures to ensure that patches are consistently applied within the time allowed.

## tl:dr

Server:

```yaml
profile: cis-1.6
selinux: true
secrets-encryption: true
write-kubeconfig-mode: 0640
use-service-account-credentials: true
kube-controller-manager-arg:
- bind-address=127.0.0.1
- use-service-account-credentials=true
- tls-min-version=VersionTLS12
- tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
kube-scheduler-arg:
- tls-min-version=VersionTLS12
- tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
kube-apiserver-arg:
- tls-min-version=VersionTLS12
- tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- authorization-mode=RBAC,Node
- anonymous-auth=false
- audit-policy-file=/etc/rancher/rke2/audit-policy.yaml
- audit-log-mode=blocking-strict
- audit-log-maxage=30
kubelet-arg:
- protect-kernel-defaults=true
- read-only-port=0
- authorization-mode=Webhook
```

Now run:

```bash
chmod 0640 /etc/rancher/rke2/*
chmod 0700 /var/lib/rancher/rke2/agent/pod-manifests
chmod 0700 /var/lib/rancher/rke2/agent/etc
find /var/lib/rancher/rke2/agent/ -maxdepth 1 -type f -name "*.kubeconfig" -exec chmod 0640 {} \;
find /var/lib/rancher/rke2/agent/ -maxdepth 1 -type f -name "*.crt" -exec chmod 0600 {} \;
find /var/lib/rancher/rke2/agent/ -maxdepth 1 -type f -name "*.key" -exec chmod 0600 {} \;
chmod 0640 /var/lib/rancher/rke2/data
chmod 0750 /var/lib/rancher/rke2/server/manifests /var/lib/rancher/rke2/server/logs
chmod 0600 /var/lib/rancher/rke2/server/token
```

Agent:

```yaml
token: $TOKEN
server: https://$RKE_SERVER:9345
write-kubeconfig-mode: 0640
profile: cis-1.6
kube-apiserver-arg:
- authorization-mode=RBAC,Node
kubelet-arg:
- protect-kernel-defaults=true
- read-only-port=0
- authorization-mode=Webhook
```

Now run:

```bash
chmod 0640 /etc/rancher/rke2/*
chmod 0700 /var/lib/rancher/rke2/agent/pod-manifests
chmod 0700 /var/lib/rancher/rke2/agent/etc
find /var/lib/rancher/rke2/agent/ -maxdepth 1 -type f -name "*.kubeconfig" -exec chmod 0640 {} \;
find /var/lib/rancher/rke2/agent/ -maxdepth 1 -type f -name "*.crt" -exec chmod 0600 {} \;
find /var/lib/rancher/rke2/agent/ -maxdepth 1 -type f -name "*.key" -exec chmod 0600 {} \;
```