#!/bin/bash
#
# Jose' Vargas <https://github.com/josev814>
# To use this plugin, place it in a directory such as /var/local/bin, and make it executable
# Then in /etc/denyhosts.conf look for PLUGIN_PURGE, and set the path to the file.
# ex: PLUGIN_PURGE=/var/local/bin/iptablesRemoveIp.sh
#
# function to purge an ip from the iptables input
function purgeFromIpTables () {
  #get the iptables location and rule id from the args passed
  ipTablesLocation=$1
  ipRuleId=$2
  
  #remove the ip rule that was dropped from deny.hosts
  $ipTablesLocation -D INPUT $ipRuleId
}

#function to write to the log file determined by /etc/denyhosts.conf
function writeToLog () {
  #Get log file location
  logFileLocation=`cat /etc/denyhosts.conf | grep ^DAEMON_LOG\ = | awk '{ print $3 }'`
  
  #use the default logfileformat
  #2016-07-13 21:11:14,380 - denyfileutil: INFO     num entries purged: 1
  
  # Get the current time for logging purposes
  time=`date +"%Y-%m-%d %T"`

  if [[ $1 == 1 ]]
  then
    #get the iprule args to write to log and delete from iprules from the passed argument
    ipRule=$2
    
    #write what we're doing to the log
    echo "$time,32 - iptablesRemoveIp       : INFO  Deleting $ipRule from iptables INPUT rules" >> $logFileLocation
  else
    echo "$time,34 - iptablesRemoveIp       : INFO  No rules to delete from iptables INPUT rules" >> $logFileLocation
  fi
}

# Get the IP from the cli
ip=$1

# Get settings from denyhosts.conf
ipTablesLocation=`cat /etc/denyhosts.conf | grep IPTABLES\ = | awk '{ print $3 }'`

# Get the output of iptables INPUTS where it matches the given ip and action of DROP then return an array of the ids of the iprules
ipRuleIds=(`$ipTablesLocation -L INPUT --line-numbers -n | grep $ip | grep DROP | awk '{ print $1 }'`)

#change the IFS to explode content into an array using new line characters
IFS=$'\r\n'
# Get the output of iptables INPUTS where it matches the ip and DROP and get the target, protocol opt source and destination for the log
ipRules=(`$ipTablesLocation -L INPUT --line-numbers -n | grep $ip | grep DROP | awk '{ print $2 $3 $4 $5 $6 }'`)

#change IFS back to the original value
unset IFS

ruleCount=${#ipRuleIds[@]}

#if the rule count is 1 then we don't have an array
if [[ $ruleCount -eq 1 ]]
then
  writeToLog 1 $ipRules
  purgeFromIpTables $ipTablesLocation $ipRuleIds
else
  #loop through the returned ip rules
  #start at the highest rule and go to the lowest to prevent other rules from being deleted on accident.
  while [[ $ruleCount -gt 0 ]]
  do
    #decrement ruleCount down 1 since arrays start at 0 and not one, 
    #and keep reducing util we have 0 elements left
    let ruleCount-=1
    
    ipRuleId=${ipRuleIds[ruleCount]}
    ipRule=${ipRules[ruleCount]}

    #as long as the ipRuleId is greater than 0 it's valid
    if [[ $ipRuleId -gt 0 ]]
    then
      writeToLog 1 "$ipRules"
      purgeFromIpTables $ipTablesLocation $ipRuleIds
    else
      #write that nothing was done to ipTables
      writeToLog 0
    fi
    
  done
fi
