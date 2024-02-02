#!/bin/bash
# clemenko@gmail.com
#here is how to use the API to push a logon banner as well as header and footers for classification. 
# https://www.astrouxds.com/components/classification-markings/

class=$1

if [ -z $class ]; then 
 echo "$RED [warn]$NORMAL Please ensure you have kubeconfig and classification to the command."
 echo "  $BLUE Use:$NORMAL $0 <CLASSIFICATION> "
 echo "  $BLUE Use:$NORMAL $0 TS "
 exit
fi

# check for kubctl
command -v kubectl >/dev/null 2>&1 || { echo -e "$RED" " ** Kubectl was not found. Please install. ** " "$NO_COLOR" >&2; exit 1; }

# check for kubeconfig
if [ $(kubectl get ns cattle-system --no-headers | wc -l) != "1" ]; then echo -e "$RED" " ** kubeconfig was not found. Please install. ** " "$NO_COLOR" >&2; exit 1; fi

#gov logon message
export govmessage=$(cat <<EOF
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.By using this IS (which includes any device attached to this IS), you consent to the following conditions:-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.-At any time, the USG may inspect and seize data stored on this IS.-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
EOF
)

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

*) echo "Usage: $0  <SERVER> {clear | TS | U  }"; exit 1

esac
