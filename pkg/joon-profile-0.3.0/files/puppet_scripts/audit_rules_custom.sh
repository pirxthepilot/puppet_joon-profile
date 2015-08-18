#!/bin/bash
# Generate custom audit.rules entries
# Managed by Puppet

# Create custom audit rule
RULESFILE='/etc/audit/rules.d/cis01.rules'
/bin/find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | /bin/awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged" }' > $RULESFILE
/bin/chmod 640 $RULESFILE

# Enable auditing processes prior to auditd
GRUBCONF='/etc/grub.conf'
/bin/sed -i 's/\ audit=1//g' $GRUBCONF
/bin/sed -i '/kernel\ \/vmlinuz/ s/$/ audit=1/g' $GRUBCONF
