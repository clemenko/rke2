# My Full Demo Stack

Both these scripts are meant to simplify the building of a demo stack for StackRox. With both you will get :

- [DigitalOcean](http://digitalocean.com) - VMs
- [Ubuntu](http://ubuntu.com) - [Rocky Linux](https://rockylinux.org/)
- [RKE2](https://docs.rke2.io/) - RKE2 Kube / [K3s](http://k3s.io) - K3s Kube
- [Rancher](https://rancher.com/products/rancher) - Rancher Cluster Manager
- [Longhorn](http://longhorn.io) - Stateful storage
- [Traefik](http://traefik.io) - Ingress
- [Jenkins](http://jenkins.io) - CI/CD
- [Prometheus](http://prometheus.io) - Metrics
- [Grafana](http://grafana.com) - Graphing
- [Openfaas](http://openfaas.com) - Serverless
- [Graylog](http://https://www.graylog.org) - Logging
- [StackRox](http://stackrox.com) - Security / [NeuVector](https://github.com/neuvector/neuvector)
- [Linkerd](http://linkerd.io) - Service Mesh
- [KeyCloak](http://keycloak.org) - Authentication
- [Harbor](http://goharbor.io) - Registry
- [Code Server](https://github.com/cdr/code-server) - Web IDE

Please pay attention to the variables at the stop of the scripts.

Any questions please feel free to create an issue or email me at clemenko@gmail.com.


## k3s

Specifically this script is designed to be as fast as possible. How about a recording?

[![ DigitalOcean, Ubuntu, K3s, and StackRox in under 6 minutes. Full Stack - asciinema ](https://asciinema.org/a/mGh0936Gl8pmbNkZYFFpKbt6X.png)](https://asciinema.org/a/mGh0936Gl8pmbNkZYFFpKbt6X?autoplay=1)

---

## rke2/rancher notes

## automated importing of clusters

```bash
password=Pa22word
rancherUrl=rancher.dockr.life
clusterName=newCluster
token=$(curl -sk -X POST https://$rancherUrl/v3-public/localProviders/local?action=login -H 'content-type: application/json' -d '{"username":"admin","password":"'$password'"}' | jq -r .token)

curl -sk https://$rancherUrl/v1/provisioning.cattle.io.clusters -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"type":"provisioning.cattle.io.cluster","metadata":{"namespace":"fleet-default","name":"'$clusterName'"},"spec":{}}' > /dev/null 2>&1 

clusterId=$( curl -sk https://$rancherUrl/apis/provisioning.cattle.io/v1/namespaces/fleet-default/clusters/$clusterName -H "Authorization: Bearer $token" | jq -r .status.clusterName)

curl -sk https://$rancherUrl/v3/clusterregistrationtokens -H 'content-type: application/json' -H "Authorization: Bearer $token"  | jq -r ' .data[] | select(.clusterId=="'$clusterId'") | .insecureCommand' 
```

## api for moving namepsaces to projects

```bash
## move NS to project
password=Pa22word
rancherUrl=rancher.dockr.life
projectName=newProject
clusterName=local
nameSpace=harbor
unset projectId

# get Token
token=$(curl -sk -X POST https://$rancherUrl/v3-public/localProviders/local?action=login -H 'content-type: application/json' -d '{"username":"admin","password":"'$password'"}' | jq -r .token)

# If project
projectId=$(curl -sk https://$rancherUrl/v3/projects -H 'content-type: application/json' -H "Authorization: Bearer $token" | jq '.data[] | select(.name=="newProject") | .id')

# create project
if [ -z $projectId ]; then 
  projectId=$(curl -sk https://$rancherUrl/v3/projects -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"type":"project","name":"'$projectName'","annotations":{},"labels":{},"clusterId":"'$clusterName'"}' | jq -r .id | awk -F: '{print $2}')
fi

# get api token
token=$(curl -sk -X POST https://$rancherUrl/v3-public/localProviders/local?action=login -H 'content-type: application/json' -d '{"username":"admin","password":"'$password'"}' | jq -r .token)

# get resource verison
resourceVersion=$(curl -sk https://$rancherUrl/api/v1/namespaces/$nameSpace -H 'content-type: application/json' -H 'accept: application/json' -H "Authorization: Bearer $token" |jq -r .metadata.resourceVersion)

# move NS to new project
curl -sk https://$rancherUrl/v1/namespaces/$nameSpace -H 'content-type: application/json' -H 'accept: application/json' -H "Authorization: Bearer $token" -X PUT  -d '{"id":"'$nameSpace'","metadata":{"annotations":{"field.cattle.io/projectId":"'$clusterName':'$projectId'"},"labels":{"field.cattle.io/projectId":"'$projectId'"},"name":"'$nameSpace'","resourceVersion": "'$resourceVersion'"}}'

```
