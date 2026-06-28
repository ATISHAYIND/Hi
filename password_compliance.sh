#!/bin/bash

# Backup files
cp /etc/security/pwquality.conf /etc/security/pwquality.conf_$(date +%d%b%y)
cp /etc/login.defs /etc/login.defs_$(date +%d%b%y)

# Update pwquality.conf
sed -i 's/^minlen.*/minlen = 14/' /etc/security/pwquality.conf
sed -i 's/^dcredit.*/dcredit = -1/' /etc/security/pwquality.conf
sed -i 's/^ucredit.*/ucredit = -1/' /etc/security/pwquality.conf
sed -i 's/^lcredit.*/lcredit = -1/' /etc/security/pwquality.conf
sed -i 's/^ocredit.*/ocredit = -1/' /etc/security/pwquality.conf
sed -i 's/^retry.*/retry = 3/' /etc/security/pwquality.conf
sed -i 's/^maxrepeat.*/maxrepeat = 3/' /etc/security/pwquality.conf
sed -i 's/^maxclassrepeat.*/maxclassrepeat = 4/' /etc/security/pwquality.conf
sed -i 's/^difok.*/difok = 4/' /etc/security/pwquality.conf

# Update login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN   14/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

# Update pwhistory.conf (RHEL8/9)
if [ -f /etc/security/pwhistory.conf ]; then
    cp /etc/security/pwhistory.conf /etc/security/pwhistory.conf_$(date +%d%b%y)
    sed -i 's/^remember.*/remember = 5/' /etc/security/pwhistory.conf
fi

exit 0
