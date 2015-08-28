#!/bin/bash
# NOTE: Run as superuser!!
# Auto build and deploy this puppet module
# USAGE: sudo ./deploy_puppet_module.sh <environment>
#
# This will deploy the module to its rightful place:
# - /etc/puppet/environments/<environment>/modules
# v1.1


if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

ENVIRONMENT="$1"
MODPATH=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
MODNAME="`printf '%s\n' "${MODPATH##*/}"`"
PKGPATH="$MODPATH/pkg"

# Environment tests
if [ -z "$ENVIRONMENT" ]; then
	echo "You must specify an environment."
	exit 1
fi
if [ ! -d "/etc/puppet/environments/$ENVIRONMENT" ]; then
	echo "The environment '$ENVIRONMENT' does not exist."
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
echo "Done!"
