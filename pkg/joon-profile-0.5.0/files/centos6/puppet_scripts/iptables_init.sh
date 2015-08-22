#!/bin/bash
# Initialize IPtables script - run once only

IPTABLESCONF='/etc/sysconfig/iptables'
/bin/cat <<EOT > $IPTABLESCONF
# Firewall configuration written by system-config-firewall
# Manual customization of this file is not recommended.
# Initialized by Puppet according to CIS standards.

*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:Puppet-Custom-INPUT - [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A INPUT -j Puppet-Custom-INPUT
-A INPUT -m limit --limit 3/hour -j LOG
-A INPUT -j DROP
-A FORWARD -m limit --limit 3/hour -j LOG
-A FORWARD -j DROP
COMMIT
EOT

# Restart IPtables
/sbin/service iptables restart
