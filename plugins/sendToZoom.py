#!/usr/bin/env python
#
# Jose' Vargas <https://github.com/josev814>
# This plugin allows deny host to send a blocked ip to slack as a notification
# To enable the plugin edit /etc/denyhosts.conf
# Uncomment PLUGIN_DENY and point it to the location of this file
# create zoom.conf in the plugins directory and set the zoom url, path and webhooktoken
#   or cd to your plugins directory and run python sendToZoom.py. This allows the plugin to create the file on it's own
#   then edit the created zoom.conf file to match the settings you need.
# if the denyhosts log shows plugin returned 32256, chmod +x this file so that it's executable
# Tested on Python 2.6, 2.7.13
#

import sys
import os
#import urllib2
import socket
import re
import json
import requests
from configparser import ConfigParser

# Enable/Disable the option to include/exclude ips in slack messages
enableIps = False
ZOOMTOKEN = ''
ZOOMURL = ''
ZOOMPATH = ''

# set the slack options
zoomConfig = os.path.dirname(os.path.realpath(__file__)) + '/zoom.conf'
config = ConfigParser()
if os.path.exists(zoomConfig) is False:
    config.add_section('default')
    config.set('default', 'url', 'https://inbots.zoom.us/incoming/hook/')
    config.set('default', 'webhooktoken', 'xxxxxx')
    config.set('default', 'path', 'xxxxxx')
    with open(zoomConfig, 'w') as configfile:
        config.write(configfile)

config.read(zoomConfig)
if 'default' in config:
    if 'url' in config['default'] and re.match(r'([\w:/.]+)', config['default']['url'], re.IGNORECASE):
        ZOOMURL = re.findall(r'([\w:/.]+)', config['default']['url'], re.IGNORECASE)[0]
    if 'webhooktoken' in config['default'] and re.match(r'([\w\d]+)', config['default']['webhooktoken'], re.IGNORECASE):
        ZOOMTOKEN = re.findall(r'([\w\d]+)', config['default']['webhooktoken'], re.IGNORECASE)[0]
    # channel to post in slack, include the # in front of the channel ex: #systems
    if 'path' in config['default'] and re.match(r'([\w\d]+)', config['default']['path'], re.IGNORECASE):
        ZOOMPATH = re.findall(r'([\w\d]+)', config['default']['path'], re.IGNORECASE)[0]

# Zoom Web Hook ex: https://inbots.zoom.us/incoming/hook/xxxxxxxxxxxxxxxxxxxx
zoomWebHook = ZOOMURL + ZOOMPATH + '?format=full'

# Get Server Info
serverName = socket.gethostbyname_ex(socket.gethostname())[0]

if enableIps:
    serverIps = socket.gethostbyname_ex(socket.gethostname())[2]
    if len(serverIps) > 1:
        externalServerIp = socket.gethostbyname_ex(socket.gethostname())[2][1]
        internalServerIp = socket.gethostbyname_ex(socket.gethostname())[2][0]
        # Set the Message that's sent
        message = '{0} ip blocked on {1} ({2} / {3})'.format(sys.argv[1], serverName, externalServerIp, internalServerIp)
    else:
        serverIp = socket.gethostbyname_ex(socket.gethostname())[2][0]
        # Set the Message that's sent
        message = '{0} ip blocked on {1} ({2})'.format(sys.argv[1], serverName, serverIp)
else:
    message = '{0} ip blocked on {1}'.format(sys.argv[1], serverName)
        

# if channel is set use the channel defined, otherwise post to the channel the webhook was made for
dataObject = {
    'head': {
        'text': 'Denyhosts',
        'style': {
            'bold': True
        }
    },
    'body': [
        {
            'type': 'message',
            'text': '{0}'.format(message)
        }
    ]
}

data = '{0}'.format(json.dumps(dataObject))

if zoomWebHook != "":
    try:
        request = requests.post(
            zoomWebHook,
            data,
            headers={'Content-Type': 'application/json', 'Authorization': ZOOMTOKEN}
        )
    except requests.exceptions.SSLError:
        #this is needed in python 2.6.x on CentOS
        request = requests.post(
            zoomWebHook,
            data,
            headers={'Content-Type': 'application/json', 'Authorization': ZOOMTOKEN},
            verify=False
        )

sys.exit(0)
