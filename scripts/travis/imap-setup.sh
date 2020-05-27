#!/bin/sh -e

#
# ### This is a script to setup a dovecot imap server for testing rml_imap
#

#
# Declare the important path variables
#

# Directories used in the system
BASEDIR=$(git rev-parse --show-toplevel)
BUILDDIR="${BASEDIR}/build/ci/imap"
TRAVISDIR="${BASEDIR}/scripts/travis"

# The paths to the main files used for dovecot
CONFPATH="${BUILDDIR}/dovecot/fr_dovecot.conf"
PASSPATH="${BUILDDIR}/dovecot/fr_dovecot.passwd"
MAILPATH="${BUILDDIR}/dovecot/fr_dovecot_mail"

# The path to the two log files
LOGPATH="${BUILDDIR}/log/fr_dovecot.log"
LOGINFOPATH="${BUILDDIR}/log/fr_dovecot-info.log"

#
# Create all the necessary files
#
echo "BASEDIR: ${BASEDIR}"
echo "BUILDDIR: ${BUILDDIR}"

# Create folders for running, logging, and all parents
mkdir -p "${BUILDDIR}/dovecot"
mkdir -p "${BUILDDIR}/log"

echo "CONFPATH: ${CONFPATH}"
echo "PASSPATH: ${PASSPATH}"
echo "MAILPATH: ${MAILPATH}"

# Load the config file into the build directory
cp "${TRAVISDIR}/dovecot/fr_dovecot.conf" "${CONFPATH}"

# Make sure there is a password directory
touch  "${PASSPATH}"

# Make the mail folder if it does not already exist
if [ ! -d ${MAILPATH} ]; then
	mkdir ${MAILPATH}
fi

# Make sure there are log files
touch "${LOGPATH}"
touch "${LOGINFOPATH}" 

#
# TODO: Add users to the password file
#

USER1P=$(doveadm pw -p test1 -s CRYPT)
USER2P=$(doveadm pw -p test2 -s CRYPT)
USER3P=$(doveadm pw -p test3 -s CRYPT)

echo "\
test1:${USER1P}:::::: 
" >"${PASSPATH}"

echo "\
test2:${USER2P}:::::: 
" >>"${PASSPATH}"

echo "\
test3:${USER3P}:::::: 
" >>"${PASSPATH}"

#
# Assemble the config file
#

# Add the path to the log files
echo "
log_path = ${LOGPATH}
info_log_path = ${LOGINFOPATH} \
" >> "${CONFPATH}"

# Add the Password File to the config
echo  "
passdb {
	driver = passwd-file
    	args = ${PASSPATH} # worked
}" >> "${CONFPATH}"

# Add the mail directory to the config
echo "
mail_location = mbox:/etc/dovecot/fr_temp_mail \
" >> "${CONFPATH}"
