#!/bin/bash
# Regular scheduled ClamAV scan
# Managed by Puppet

#SCAN_DIRS="/home /root /opt"
SCAN_DIRS="/"
LOG_FILE="/var/log/clamav/clamdscan.log"

if [ "$1" == "verbose" ]; then
    VERBOSE="-v"
else
    VERBOSE=""
fi

printf "\n======================================\n" >> $LOG_FILE
printf "`date`\n" >> $LOG_FILE

/usr/bin/clamdscan $SCAN_DIRS --fdpass --multiscan -l $LOG_FILE $VERBOSE

printf "======================================\n\n" >> $LOG_FILE
