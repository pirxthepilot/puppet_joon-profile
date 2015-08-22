#!/bin/bash
# Add/delete IPtables rules
# from the Puppet-Custom-INPUT chain
#
# Syntax: command [add|update|delete] <srcip> <protocol> <dstport>

ACTION="$1"
SRCIP="$2"
PROTOCOL="$3"
DSTPORT="$4"
IPTABLES='/sbin/iptables'
SERVICE='/sbin/service'
SAVE='/sbin/iptables-save'
GREP='/bin/grep'
CHAIN='Puppet-Custom-INPUT'
CONFIG='/etc/sysconfig/iptables'

if [ "$ACTION" == "add" ]; then
    iptablescmd='-A'
elif [ "$ACTION" == "delete" ]; then
    iptablescmd='-D'
elif [ "$ACTION" == "update" ]; then
    iptablescmd='-A'
fi

if [ -z "$iptablescmd" ]; then
    echo "Invalid action"
    exit 1
fi

# First, restart IPtables
$SERVICE iptables restart

# If updating, delete the rule with the same protocol and port
if [ "$ACTION" == "update" ]; then
    readarray rules < <($GREP "Puppet-Custom-INPUT.*\-p $PROTOCOL.*\-\-dport $DSTPORT \-j ACCEPT" $CONFIG)
    for rule in "${rules[@]}"
    do
        flushcmd=`echo $rule | awk '!($1="")'`
        $IPTABLES -D$flushcmd
    done
fi

# IPtables command
$IPTABLES $iptablescmd $CHAIN -s $SRCIP -p $PROTOCOL -m state --state NEW -m $PROTOCOL --dport $DSTPORT -j ACCEPT

# Save to config
$SAVE > $CONFIG

