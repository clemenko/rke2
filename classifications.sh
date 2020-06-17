#!/bin/bash
# clemenko@gmail.com
#here is how to use the API to push a logon banner as well as header and footers for classification. 
# https://www.astrouxds.com/components/classification-markings/

rancherUrl=$1
class=$2
password=Pa22word

if [ -z $rancherUrl ]; then 
 echo "$RED [warn]$NORMAL Please add the server name and classification to the command."
 echo "  $BLUE Use:$NORMAL $0 <SERVER> <CLASSIFICATION> "
 echo "  $BLUE Use:$NORMAL $0 rancher.rfed.io TS "
 exit
fi

#########

function get_password (){
#read the admin password
echo -n " - Rancher Admin Password for $rancherUrl: "; read -s password; echo
}

# get current version
resourceVersion=$(curl -sk https://$rancherUrl/v1/management.cattle.io.settings/ui-banners | jq -r .metadata.resourceVersion)

# get Token
get_password
token=$(curl -sk -X POST https://$rancherUrl/v3-public/localProviders/local?action=login -H 'content-type: application/json' -d '{"username":"admin","password":"'$password'"}' | jq -r .token)

#gov logon message
export govmessage=$(cat <<EOF
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.By using this IS (which includes any device attached to this IS), you consent to the following conditions:-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.-At any time, the USG may inspect and seize data stored on this IS.-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
EOF
)

case $2 in
U )
#unclass
curl -sk -X PUT https://$rancherUrl/v1/management.cattle.io.settings/ui-banners -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"id":"ui-banners","type":"management.cattle.io.setting","apiVersion":"management.cattle.io/v3","customized":false,"default":"{}","kind":"Setting","metadata":{"name":"ui-banners","resourceVersion":"'$resourceVersion'"},"source":null,"value":"{\"bannerHeader\":{\"background\":\"#007a33\",\"color\":\"#ffffff\",\"textAlignment\":\"center\",\"fontWeight\":null,\"fontStyle\":null,\"fontSize\":\"14px\",\"textDecoration\":null,\"text\":\"UNCLASSIFIED\"},\"bannerFooter\":{\"background\":\"#007a33\",\"color\":\"#ffffff\",\"textAlignment\":\"center\",\"fontWeight\":null,\"fontStyle\":null,\"fontSize\":\"14px\",\"textDecoration\":null,\"text\":\"UNCLASSIFIED\"},\"bannerConsent\":{\"background\":\"#ffffff\",\"color\":\"#000000\",\"textAlignment\":\"left\",\"fontWeight\":null,\"fontStyle\":null,\"fontSize\":\"14px\",\"textDecoration\":false,\"text\":\"'"$govmessage"'\",\"button\":\"Accept\"},\"showHeader\":\"true\",\"showFooter\":\"true\",\"showConsent\":\"true\"}"}' > /dev/null 2>&1
;;

TS )
#top secret
curl -sk -X PUT https://$rancherUrl/v1/management.cattle.io.settings/ui-banners -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"id":"ui-banners","type":"management.cattle.io.setting","apiVersion":"management.cattle.io/v3","customized":false,"default":"{}","kind":"Setting","metadata":{"name":"ui-banners","resourceVersion":"'$resourceVersion'"},"source":null,"value":"{\"bannerHeader\":{\"background\":\"#fce83a\",\"color\":\"#ffffff\",\"textAlignment\":\"center\",\"fontWeight\":null,\"fontStyle\":null,\"fontSize\":\"14px\",\"textDecoration\":null,\"text\":\"TOP SECRET//SCI\"},\"bannerFooter\":{\"background\":\"#fce83a\",\"color\":\"#ffffff\",\"textAlignment\":\"center\",\"fontWeight\":null,\"fontStyle\":null,\"fontSize\":\"14px\",\"textDecoration\":null,\"text\":\"TOP SECRET//SCI\"},\"bannerConsent\":{\"background\":\"#ffffff\",\"color\":\"#000000\",\"textAlignment\":\"left\",\"fontWeight\":null,\"fontStyle\":null,\"fontSize\":\"14px\",\"textDecoration\":false,\"text\":\"'"$govmessage"'\",\"button\":\"Accept\"},\"showHeader\":\"true\",\"showFooter\":\"true\",\"showConsent\":\"true\"}"}' > /dev/null 2>&1
;;

clear )
#clear
curl -sk -X PUT https://$rancherUrl/v1/management.cattle.io.settings/ui-banners -H 'content-type: application/json' -H "Authorization: Bearer $token" -d '{"id":"ui-banners","type":"management.cattle.io.setting","apiVersion":"management.cattle.io/v3","customized":false,"default":"{}","kind":"Setting","metadata":{"name":"ui-banners","resourceVersion":"'$resourceVersion'"},"source":null,"value":"{\"bannerHeader\":{\"background\":\"#ffffff\",\"color\":\"#000000\",\"textAlignment\":\"center\",\"fontWeight\":null,\"fontStyle\":null,\"fontSize\":\"14px\",\"textDecoration\":null,\"text\":\"\"},\"bannerFooter\":{\"background\":\"#ffffff\",\"color\":\"#000000\",\"textAlignment\":\"center\",\"fontWeight\":null,\"fontStyle\":null,\"fontSize\":\"14px\",\"textDecoration\":null,\"text\":\"\"},\"bannerConsent\":{\"background\":\"#ffffff\",\"color\":\"#000000\",\"textAlignment\":\"left\",\"fontWeight\":null,\"fontStyle\":null,\"fontSize\":\"14px\",\"textDecoration\":false,\"text\":\"\",\"button\":\"\"},\"showHeader\":\"false\",\"showFooter\":\"false\",\"showConsent\":\"false\"}"}' > /dev/null 2>&1
;;

*) echo "Usage: $0  <SERVER> {clear | TS | U  }"; exit 1

esac
