#!/usr/bin/env python
#
# Jose' Vargas <https://github.com/josev814>
# This plugin allows deny host to send a blocked ip to slack as a notification
# To enable the plugin edit /etc/denyhosts.conf
# Uncomment PLUGIN_DENY and point it to the location of this file
# create slack.conf in the plugins directory and set the slack url, webhooktoken, channel
#   or cd to your plugins directory and run python sendToSlack.py. This allows the plugin to create the file on it's own
#   then edit the created slack.conf file to match the settings you need.
# chmod +x this file so that it's executable, or the logs will show plugin returned 32256
# Tested on Python 2.6, 2.7.13
#

import sys
import os
import socket
import re
import json
import requests
from configparser import ConfigParser

# Enable/Disable the option to include/exclude ips in slack messages
enableIps = False
SLACKTOKEN = ''
SLACKURL = ''
SLACKCHANNEL = ''

# set the slack options
slackConfig = os.path.dirname(os.path.realpath(__file__)) + '/slack.conf'
config = ConfigParser()
if os.path.exists(slackConfig) is False:
    config.add_section('default')
    config.set('default', 'url', 'https://hooks.slack.com/services/')
    config.set('default', 'webhooktoken', 'xxx/xxx/xxx')
    config.set('default', 'channel', '')
    with open(slackConfig, 'w') as configfile:
        config.write(configfile)

config.read(slackConfig)
if 'default' in config:
    if 'url' in config['default'] and re.match(r'([\w:/.]+)', config['default']['url'], re.IGNORECASE):
        SLACKURL = re.findall(r'([\w:/.]+)', config['default']['url'], re.IGNORECASE)[0]
    if 'webhooktoken' in config['default'] and re.match(r'([\w\d\-/]+)', config['default']['webhooktoken'], re.IGNORECASE):
        SLACKTOKEN = re.findall(r'([\w\d\-/]+)', config['default']['webhooktoken'], re.IGNORECASE)[0]
    # channel to post in slack, include the # in front of the channel ex: #systems
    if 'channel' in config['default'] and re.match(r'(^[@#][\w\d\-_/.]+)', config['default']['channel'],re.IGNORECASE):
        SLACKCHANNEL = re.findall(r'([@#][\w\d\-_/.]+)', config['default']['channel'], re.IGNORECASE)[0][0]

# Slack Web Hook ex: https://hooks.slack.com/services/xxxxxxx/xxxxxxxxx/xxxxxxxxxxxxxxxxxxxx
slackWebHook = SLACKURL + SLACKTOKEN

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
    'text': '{0}'.format(message)
}

if SLACKCHANNEL != "":
    dataObject['channel'] = SLACKCHANNEL

data = '{0}'.format(json.dumps(dataObject))

if slackWebHook != "":
    request = requests.post(slackWebHook, data)

sys.exit(0)
