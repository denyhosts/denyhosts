#!/usr/bin/python
#
# Jose' Vargas <https://github.com/josev814>
# This plugin allows deny host to send a blocked ip to slack as a notification
# To enable the plugin edit /etc/denyhosts.conf
# Uncomment PLUGIN_DENY and point it to the location of this file
# Edit lines 16 and 18 to your slack web hook url and channel
# chmod +x this file so that it's executable, or the logs will show plugin returned 32256
# Tested on Python 2.7.9
#
import sys
import urllib2
import socket

# Enable/Disable the option to include/exclude ips in slack messages
enableIps=False

# set the slack options
#Slack Web Hook ex: https://hooks.slack.com/services/xxxxxxx/xxxxxxxxx/xxxxxxxxxxxxxxxxxxxx
slackWebHook=''
#channel to post in slack, include the # in front of the channel ex: #systems
channel=''

# Get Server Info
serverName=socket.gethostbyname_ex(socket.gethostname())[0]

if enableIps:
        serverIps=socket.gethostbyname_ex(socket.gethostname())[2]
        if len(serverIps) > 1:
                externalServerIp=socket.gethostbyname_ex(socket.gethostname())[2][1]
                internalServerIp=socket.gethostbyname_ex(socket.gethostname())[2][0]
                # Set the Message that's sent
                message="%s ip blocked on %s (%s / %s)" % ( sys.argv[1], serverName, externalServerIp, internalServerIp )
        else:
                serverIp=socket.gethostbyname_ex(socket.gethostname())[2][0]
                # Set the Message that's sent
                message="%s ip blocked on %s (%s)" % ( sys.argv[1], serverName, serverIp )
else:
        message="%s ip blocked on %s" % ( sys.argv[1], serverName )
        

#if channel is set use the channel defined, otherwise post to the channel the webhook was made for
if channel != "":
        data='payload={"text":"' + message + '","channel":"' + channel + '"}'
else:
        data='payload={"text":"' + message + '"}'

if slackWebHook != "":
        request = urllib2.Request(slackWebHook, data)
        call = urllib2.urlopen(request)
        call.close()

sys.exit(0)
