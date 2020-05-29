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
CONFPATH="${BUILDDIR}/dovecot_conf/fr_dovecot.conf"
PASSPATH="${BUILDDIR}/dovecot_conf/fr_dovecot.passwd"
MAILPATH="${BUILDDIR}/dovecot_conf/fr_dovecot_mail"

# The path to the two log files
LOGPATH="${BUILDDIR}/dovecot_log/fr_dovecot.log"
LOGINFOPATH="${BUILDDIR}/dovecot_log/fr_dovecot-info.log"

#
# Create all the necessary files
#

# Create folders for running, logging, and all parents
mkdir -p "${BUILDDIR}/dovecot_conf"
mkdir -p "${BUILDDIR}/dovecot_log"
mkdir -p "${BUILDDIR}/dovecot_run"

# Load the config file into the build directory
cp "${TRAVISDIR}/dovecot/fr_dovecot.conf" "${CONFPATH}"

# Make sure there is a password file
touch  "${PASSPATH}"

# Make the mail folder if it does not already exist
if [ ! -d ${MAILPATH} ]; then
	mkdir ${MAILPATH}
fi

# Make sure there are log files
touch "${LOGPATH}"
touch "${LOGINFOPATH}" 

#
# Add users to the password file
#

# Generate teh passwords
USER1P=$(doveadm pw -p test1 -s CRYPT)
USER2P=$(doveadm pw -p test2 -s CRYPT)
USER3P=$(doveadm pw -p test3 -s CRYPT)

# Add user password combinations
echo "\
user1:${USER1P}:::::: 
" >"${PASSPATH}"

echo "\
user2:${USER2P}:::::: 
" >>"${PASSPATH}"

echo "\
user3:${USER3P}:::::: 
" >>"${PASSPATH}"

#
# Assemble the config file
#

# Add the base directory
echo "
base_dir = ${BUILDDIR}/dovecot_run \
" >> "${CONFPATH}"

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
mail_location = mbox:${MAILPATH} \
" >> "${CONFPATH}"

# Set user for permissions
echo "
default_internal_user = ${USER}
default_login_user = ${USER} \
" >> "${CONFPATH}"

# Configure the imap login protocol
echo "
service imap-login {
        process_min_avail = 16
        user = ${USER}
        chroot =
        inet_listener imap {
                port = 1431
        }
} \
" >> "${CONFPATH}"

#Configure the user mailbox privileges
echo "
userdb {
        driver = static
        args = uid=stephen gid=stephen
} \
" >> "${CONFPATH}"


#
# Run the imap server
#

dovecot -c ${CONFPATH} > /dev/null 2>&1
dovecot -c ${CONFPATH} reload > /dev/null 2>&1

exit 0
