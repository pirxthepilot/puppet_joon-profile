#!/bin/bash
# Enable or disable SSSD via authconfig
#
# Usage: sssd-control.sh enable|disable

AUTHCONFIG='/usr/sbin/authconfig'
YUM='/usr/bin/yum'
OPER="$1"
KRB5_CONF='/etc/krb5.conf'
SAMBA_CONFDIR='/etc/samba'
SSSD_CONFDIR='/etc/sssd'
ODDJOB_CONFDIR='/etc/oddjobd.conf.d'

if [ -z "$OPER" ]; then
    /bin/echo 'Usage: sssd-control.sh enable|disable'
    exit 1
fi

if [ "$OPER" == "enable" ]; then
    $AUTHCONFIG --enablesssdauth --enablesssd --enablemkhomedir --update
elif [ "$OPER" == "disable" ]; then
	$AUTHCONFIG --disablesssdauth --disablesssd --disablemkhomedir --update
	/sbin/service sssd stop
	/sbin/service oddjobd stop
	/sbin/chkconfig sssd off
	/sbin/chkconfig oddjobd off
	$YUM -y remove 'sssd', 'sssd-common', 'krb5-workstation', 'samba-common', 'oddjob', 'oddjob-mkhomedir', 'openldap-clients'
	#/bin/rm -f $KRB5_CONF # Don't delete - part of default distro (CentOS minimal)
	/bin/rm -rf $SAMBA_CONFDIR
	/bin/rm -rf $SSSD_CONFDIR
	/bin/rm -rf $ODDJOB_CONFDIR
else
	/bin/echo 'Usage: sssd-control.sh enable|disable'
fi
