# Managed by puppet - do not modify!
#
# umask.sh
# Sets more secure umask settings according to CIS standards


if [ $UID -gt 199 ] && [ "`id -gn`" = "`id -un`" ]; then
	umask 027
else
	umask 077
fi
