#!/bin/bash
# NOTE: Run as superuser!!
# Auto build and deploy this puppet module
# USAGE: sudo ./deploy_puppet_module.sh <environment>
#
# This will deploy the module to its rightful place:
# - /etc/puppet/environments/<environment>/modules
# v1.2


if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

ENVIRONMENT="$1"
MODPATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
MODNAME="`printf '%s\n' "${MODPATH##*/}"`"
PKGPATH="$MODPATH/pkg"
ENVPATH='/etc/puppet/environments'

# Environment tests
if [ -z "$ENVIRONMENT" ]; then
	echo "You must specify an environment."
	exit 1
fi
if [ ! -d "$ENVPATH/$ENVIRONMENT" ]; then
	echo "The environment '$ENVIRONMENT' does not exist."
	exit 1
fi

# Confirm
echo  "WARNING: YOU ARE ABOUT TO INSTALL $MODNAME INTO"
echo -n "THE $ENVIRONMENT ENVIRONMENT. PROCEED? [y/n] "
read confirm

if [ "${confirm,,}" == "n" ]; then
    echo "ok, cancelling"
    exit 0
elif [ "${confirm,,}" != "y" ]; then
    echo "Invalid input."
    exit 1
fi

# Build
echo "Building $MODNAME on $PKGPATH.."
puppet module build $MODPATH --environment $ENVIRONMENT

if [ "$?" = "1" ]; then
	echo "Error! Exiting."
	exit 1
fi

# Adjust permissions
echo "Adjusting permissions.."
chown -R --reference=$PKGPATH $PKGPATH
find $PKGPATH -type f -exec chmod 640 {} \;
find $PKGPATH -type d -exec chmod 750 {} \;

PKGFILE=`find $PKGPATH -name *.tar.gz | sort -n | tail -n 1`

# Install
echo "Deploying $PKGFILE to $ENVIRONMENT.."
puppet module uninstall --environment $ENVIRONMENT --ignore-changes $MODNAME
puppet module install $PKGFILE --environment $ENVIRONMENT
echo "Adjusting permissions on $ENVPATH/$ENVIRONMENT.."
chown -R --reference=$ENVPATH $ENVPATH/$ENVIRONMENT
echo "Done!"
