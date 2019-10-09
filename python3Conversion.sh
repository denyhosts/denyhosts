#!/usr/bin/env bash

if [[ -d DenyHosts ]]
then
    find ./ -type f -exec sed -i 's/bin\/env python/bin\/python3/g' {} \;
    sed -i 's/ipaddr>=2.1/ip_address/g' requirements.txt
else
    echo "This script must be ran within the root of the denyhosts project\r\n"
fi