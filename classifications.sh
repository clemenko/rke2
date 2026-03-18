#!/bin/bash
# clemenko@gmail.com
#here is how to use the API to push a logon banner as well as header and footers for classification. 
# https://www.astrouxds.com/components/classification-markings/

source functions.sh

class=$1

if [ -z "$class" ]; then 
 echo "$RED [warn]$NO_COLOR Please ensure you have kubeconfig and classification to the command."
 echo "  $BLUE Use:$NO_COLOR $0 <CLASSIFICATION> "
 echo "  $BLUE Use:$NO_COLOR $0 TS "
 exit
fi

# check for kubctl
command -v kubectl >/dev/null 2>&1 || { echo -e "$RED" " ** Kubectl was not found. Please install. ** " "$NO_COLOR" >&2; exit 1; }

# check for kubeconfig
if [ $(kubectl get ns cattle-system --no-headers | wc -l) != "1" ]; then echo -e "$RED" " ** kubeconfig was not found. Please install. ** " "$NO_COLOR" >&2; exit 1; fi

case $class in
U | u )
#unclass
cat <<EOF | kubectl apply -f -  > /dev/null 2>&1
apiVersion: management.cattle.io/v3
kind: Setting
metadata:
  name: ui-banners
value: '{"bannerHeader":{"background":"#007a33","color":"#ffffff","textAlignment":"center","fontWeight":null,"fontStyle":null,"fontSize":"14px","textDecoration":null,"text":"UNCLASSIFIED//FOUO"},"bannerFooter":{"background":"#007a33","color":"#ffffff","textAlignment":"center","fontWeight":null,"fontStyle":null,"fontSize":"14px","textDecoration":null,"text":"UNCLASSIFIED//FOUO"},"bannerConsent":{"background":"#ffffff","color":"#000000","textAlignment":"left","fontWeight":null,"fontStyle":null,"fontSize":"14px","textDecoration":false,"text":"$govmessage","button":"Accept"},"showHeader":"true","showFooter":"true","showConsent":"true"}'
EOF
;;

TS | ts )
#top secret
cat <<EOF | kubectl apply -f -  > /dev/null 2>&1
apiVersion: management.cattle.io/v3
kind: Setting
metadata:
  name: ui-banners
value: '{"bannerHeader":{"background":"#fce83a","color":"#000000","textAlignment":"center","fontWeight":null,"fontStyle":null,"fontSize":"14px","textDecoration":null,"text":"TOP SECRET//SCI"},"bannerFooter":{"background":"#fce83a","color":"#000000","textAlignment":"center","fontWeight":null,"fontStyle":null,"fontSize":"14px","textDecoration":null,"text":"TOP SECRET//SCI"},"bannerConsent":{"background":"#ffffff","color":"#000000","textAlignment":"left","fontWeight":null,"fontStyle":null,"fontSize":"14px","textDecoration":false,"text":"$govmessage","button":"Accept"},"showHeader":"true","showFooter":"true","showConsent":"true"}'
EOF
;;

clear )
cat <<EOF | kubectl apply -f -  > /dev/null 2>&1
apiVersion: management.cattle.io/v3
kind: Setting
metadata:
  name: ui-banners
value: '{"bannerHeader":{"background":"#ffffff","color":"#000000","textAlignment":"center","fontWeight":null,"fontStyle":null,"fontSize":"14px","textDecoration":null,"text":""},"bannerFooter":{"background":"#ffffff","color":"#000000","textAlignment":"center","fontWeight":null,"fontStyle":null,"fontSize":"14px","textDecoration":null,"text":""},"bannerConsent":{"background":"#ffffff","color":"#000000","textAlignment":"left","fontWeight":null,"fontStyle":null,"fontSize":"14px","textDecoration":false,"text":"","button":"Accept"},"showHeader":"false","showFooter":"false","showConsent":"false"}'
EOF
;;

*) echo "Usage: $0 {clear | TS | U  }"; exit 1

esac
