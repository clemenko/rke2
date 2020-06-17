# Rancher STIG tl;dr

Just a simple guide for navigating the Rancher 2.6 STIG from DISA. There is a nice article about it from [Businesswire](https://www.businesswire.com/news/home/20220425005143/en/DISA-Validates-Rancher-Government-Solutions%E2%80%99-Security-Technical-Implementation-Guide-for-the-Rancher-Multi-cluster-Manager-2.6-for-Kubernetes).

You can download the STIG itself from [https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RGS_MCM_V1R1_STIG.zip](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RGS_MCM_V1R1_STIG.zip). The SITG viewer can be found on DISA's site at [https://public.cyber.mil/stigs/srg-stig-tools/](https://public.cyber.mil/stigs/srg-stig-tools/). For this guide I have simplified the controls and provided simple steps to ensure compliance. Hope this helps a little.

## V-252843 - Use an AUTH provider - Keycloak

The control basically states "Use Keycloak". Once Keycloak is stood up you can follow the [Rancher docs](https://rancher.com/docs/rancher/v2.6/en/admin-settings/authentication/keycloak-oidc/) for OIDC.

## V-252844 - Audit Logging

Fix Text: Ensure audit logging is enabled:

- Navigate to Triple Bar Symbol >> Explore Cluster >> local
- In the top Select ALL Namespaces from the drop down that currently says "Only User Namespaces".
- Click "deployments" under Workload menu item.
- Select "rancher" in the Deployments section under the 'cattle-system' namespace.
- Click the three dot config menu on the right.
- Choose "Edit Config".
- Scroll down to the "Environment Variables" section.
- Change the AUDIT_LEVEL value to "2" or "3" and then click "Save".

If the variable does not exist:

- Click "Add Variable".
- Keep Default key/Value Pair as "Type"
- Add "AUDIT_LEVEL" as Variable Name.
- Input "2,3" for a value.
- Click "Save".

A better option is to update Helm. Here is a best way to update the audit log level. Using Helm we can set a few things like the initial bootstrap password and number of replicas. Notice the `auditlog` settings.

```bash
helm upgrade -i rancher rancher-latest/rancher --create-namespace --namespace cattle-system --set hostname=rancher.$domain --set bootstrapPassword=bootStrapAllTheThings --set replicas=1 --set auditLog.level=2 --set auditLog.destination=hostPath
```

## V-252845 - Role must be User

This control is about adopting a tighter default user role. Basically to scope in the default permissions.

Fix Text: From the GUI, navigate to Triple Bar Symbol >> Users & Authentication. In the left navigation menu, click "Roles".

- Click "Standard User".
- At the top right, click the three dots, and then "Edit Config".
- Under "New User Default", select "No" and click "Save".
- Click "User-Base".
- At the top right, click the three dots, and then click "Edit Config".
- Under "New User Default", select "Yes", and then click "Save".

## V-252846 - Audit Record Storage

This control is for installing and using logging for maintaining application logs.

Fix Text: Enable log aggregation:
Navigate to Triple Bar Symbol.

For each cluster in  "EXPLORE CLUSTER":

- Select "Cluster".
- Select "Cluster Tools" (bottom left).
- In the "Logging Block", select "Install".
- Select the newest version of logging in the dropdown. 
- Open the "Install into Project Dropdown".
- Select the Project. (Note: Kubernetes STIG requires creating new project & namespace for deployments. Using Default or System is not best practice.)
- Click "Next".
- Review the options and click "Install".

## V-252847 - Never automatically remove or disable emergency accounts

This control ensures that the local administrator emergency account is still active.

Fix Text: Ensure local emergency admin account has not been removed and is the only Local account.

Navigate to the Triple Bar Symbol >> Users & Authentication. In the left navigation menu, click "Users".
To Create a User:

- Click "Create".
- Complete the "Add User" form. Ensure Global Permissions are set to "Administrator".
- Click "Create".

To Delete a User:

- Select the user and click "Delete".

## V-252848 - Enforce organization-defined circumstances and/or usage conditions for organization-defined accounts.

This control should be simple. Please ensure that you are a enterprise signed certificate.

Fix Text: Update the secrets to contain valid certificates.

Put the correct and valid DOD certificate and key in files called "tls.crt" and "tls.key", respectively, and then run:
`kubectl -n cattle-system create secret tls tls-rancher-ingress  --cert=tls.crt   --key=tls.key`

Upload the CA required for the certs by creating another file called "cacerts.pem" and running:
`kubectl -n cattle-system create secret generic tls-ca \   --from-file=cacerts.pem=./cacerts.pem`

The helm chart values need to be updated to include the check section:
privateCA: true
ingress:
tls:
ce: secret

Re-run helm upgrade with the new values for the certs to take effect.

## V-252849 - Prohibit or restrict the use of protocols

This control is for limiting the ports that are allowed for ingress to the Rancher UI/API.

Fix Text: Navigate to Triple Bar Symbol >> Explore Cluster >> local
From the kubectl shell (>_) execute the following:

```bash
kubectl patch -n cattle-system service rancher -p '{"spec":{"ports":[{"port":443,"targetPort":443}]}}'

# change the hostname to match your ingress URL.
export RANCHER_HOSTNAME=rancher.rfed.io

kubectl -n cattle-system patch ingress rancher -p "{\"metadata\":{\"annotations\":{\"nginx.ingress.Kubernetes.io/backend-protocol\":\"HTTPS\"}},\"spec\":{\"rules\":[{\"host\":\"$RANCHER_HOSTNAME\",\"http\":{\"paths\":[{\"backend\":{\"service\":{\"name\":\"rancher\",\"port\":{\"number\":443}}},\"pathType\":\"ImplementationSpecific\"}]}}]}}"

kubectl patch -n cattle-system service rancher --type=json -p '[{"op":"remove","path":"/spec/ports/0"}]'
```
