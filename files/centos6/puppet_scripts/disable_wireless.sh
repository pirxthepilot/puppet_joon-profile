#!/bin/bash
# Disable wireless modules (based on CIS best practices)
# Managed by Puppet

for i in $(/bin/find /lib/modules/`uname -r`/kernel/drivers/net/wireless -name "*.ko" -type f) ; do /bin/echo blacklist $i >> /etc/modprobe.d/blacklist-wireless.conf ; done
