#!/usr/bin/env sh

if [ -d DenyHosts ]
then
    py3loc=$(whereis python3 | awk '{ print $2 }')
    #using sed -i.bak to make it gnu and bsd compatible
    find `pwd` -type f -exec sed -i.bak "s/\/usr\/bin\/env python/${py3loc}/g" {} \;
    sed -i.bak 's/ipaddr>=2.1/ip_address/g' requirements.txt
    find `pwd` -type f -name "*.bak" -exec rm {} \;
else
    echo "This script must be ran within the root of the denyhosts project\r\n"
fi