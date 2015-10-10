#!/bin/bash
# Enable or disable SSSD via authconfig
#
# Usage: sssd-control.sh enable|disable

AUTHCONFIG='/usr/sbin/authconfig'
YUM='/usr/bin/yum'
OPER="$1"
SAMBA_CONFDIR='/etc/samba'
SSSD_CONFDIR='/etc/sssd'
MKHOMEDIR_CONF='/etc/oddjobd.conf.d/oddjobd-mkhomedir.conf.rpmsave'
MKHOMEDIR_CONFDIR='/etc/oddjobd.conf.d'
KRB5_CONF='/etc/krb5.conf'
KRB5_ORIGCONF='/etc/.krb5.conf.orig'
KRB5_KEYTAB='/etc/krb5.keytab'

if [ -z "$OPER" ]; then
    /bin/echo 'Usage: sssd-control.sh enable|disable'
    exit 1
fi

if [ "$OPER" == "enable" ]; then

    $AUTHCONFIG --enablesssdauth --enablesssd --enablemkhomedir --update

elif [ "$OPER" == "disable" ]; then

	# Disable SSSD features in authconfig
	$AUTHCONFIG --disablesssdauth --disablesssd --disablemkhomedir --update

	# Leave AD domain (Note: Needs entering root password)
	#/usr/bin/net ads leave

	# Destroy kerberos sessions/tickets
	/usr/bin/kdestroy -A
	/bin/rm -f $KRB5_KEYTAB

	# Uninstall packages
	$YUM -y --remove-leaves remove sssd* krb5-workstation samba-common oddjob-mkhomedir openldap-clients

	# Config file cleanup
	/bin/rm -f $MKHOMEDIR_CONF
	/bin/rmdir --ignore-fail-on-non-empty $MKHOMEDIR_CONFDIR
	/bin/cp -f $KRB5_ORIGCONF $KRB5_CONF
	/bin/rm -rf $SAMBA_CONFDIR
	/bin/rm -rf $SSSD_CONFDIR

else
	/bin/echo 'Usage: sssd-control.sh enable|disable'
fi
