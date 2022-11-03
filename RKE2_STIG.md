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

## V-254558

The Kubernetes API server must have the insecure port flag disabled.

Fix Text:


## V-254559

## V-254560

## V-254561

## V-254562

## V-254563

## V-254564

## V-254565

## V-254566

## V-254567

## V-254568

## V-254569

## V-254570

## V-254571

## V-254572

## V-254573

## V-254574

## V-254575
