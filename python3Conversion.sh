#!/usr/bin/env sh

if [ -d DenyHosts ]
then
    py3loc=$(whereis python3 | awk '{ print $2 }')
    if [ "${py3loc}" != '' ]
    then
        py3loc=`echo "${py3loc}" | sed 's/\//\\\\\//g'`
        #using sed -i.bak to make it gnu and bsd compatible
        find `pwd` -type f | xargs sed -i.bak "s/\/usr\/bin\/env python/${py3loc}/g"
        sed -i.bak 's/ipaddr>=2.1/ip_address/g' requirements.txt
        find `pwd` -type f -name "*.bak" | xargs rm {} \;
    fi
else
    echo "This script must be ran within the root of the denyhosts project\r\n"
fi