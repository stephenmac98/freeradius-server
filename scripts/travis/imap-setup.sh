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
RUNDIR="${BUILDDIR}/dovecot_run"
TLSRUNDIR="${BUILDDIR}/dovecot_tls_run"
CERTDIR="${BASEDIR}/raddb/certs/rsa"

# The paths to the the configs for the different instances
CONF="${BUILDDIR}/dovecot_conf/fr_dovecot.conf"
TLSCONF="${BUILDDIR}/dovecot_conf/fr_tls_dovecot.conf"

# PATHS to essential files for the config
PASSPATH="${BUILDDIR}/dovecot_conf/fr_dovecot.passwd"
MAILPATH="${BUILDDIR}/dovecot_conf/fr_dovecot_mail"

# The path to the two log files
LOGPATH="${BUILDDIR}/dovecot_log/fr_dovecot.log"
LOGINFOPATH="${BUILDDIR}/dovecot_log/fr_dovecot-info.log"

#
# Create all the necessary files
#

# Stop any currently running fr_dovecot instances
sh ${TRAVISDIR}/imap-stop.sh > /dev/null 2>&1 

# Make the build directory
mkdir -p "${BUILDDIR}"

# Create folders for running, logging, and all parents
mkdir -p "${BUILDDIR}/dovecot_conf"
mkdir -p "${BUILDDIR}/dovecot_log"
mkdir -p "${RUNDIR}"
mkdir -p "${TLSRUNDIR}"

# Make sure there is a password file
touch  "${PASSPATH}"

# Make the mail folder
mkdir -p "${MAILPATH}"

# Make sure there are log files
touch "${LOGPATH}"
touch "${LOGINFOPATH}" 

#
# Add users to the password file
#

# Generate the passwords
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

# Load the config file into the build directory
cp "${TRAVISDIR}/dovecot/fr_dovecot.conf" "${CONF}"
cp "${TRAVISDIR}/dovecot/fr_dovecot.conf" "${TLSCONF}"

# Configure the imap service on a certain port
echo "
instance_name = "fr_dovecot"

ssl = no

base_dir = ${RUNDIR}

service imap-login {
        process_min_avail = 16
        user = ${USER}
        chroot =
        inet_listener imap {
                port = 1430
        }
} \
" >> "${CONF}"

echo "
instance_name = "fr_tls_dovecot"


base_dir = ${TLSRUNDIR}

service imap-login {
        process_min_avail = 16
        user = ${USER}
        chroot =
        inet_listener imap {
                port = 1431
        }
	inet_listener imaps {
		port = 1432
	}
} 
ssl = yes
# TLS specific configurations
#ssl = required
#ssl_cert = ${CERTDIR}/server.pem
#ssl_key = ${CERTDIR}/server.key
#ssl_client_ca_file = 
#ssl_verify_client_cert = yes
#auth_ssl_require_client_cert=yes
" >> "${TLSCONF}"

#
# Add path's into conf file
#
> ${TRAVISDIR}/imap-stop.sh
for CONFPATH in $CONF $TLSCONF
do
# Add the path to the log files
echo "
log_path = ${LOGPATH}
info_log_path = ${LOGINFOPATH} \
" >> "${CONFPATH}"

# Add the Password File to the config
echo  "
passdb {
	driver = passwd-file
    	args = ${PASSPATH}
}" >> "${CONFPATH}"

# Add the mail directory to the config
echo "
mail_location = maildir:${MAILPATH} \
" >> "${CONFPATH}"

# Set user for permissions
echo "
default_internal_user = ${USER}
default_login_user = ${USER} \
" >> "${CONFPATH}"

#Configure the user mailbox privileges
echo "
userdb {
        driver = static
        args = uid=${USER} gid=${USER}
} \
" >> "${CONFPATH}"


#
# Run the imap server
#

dovecot -c ${CONFPATH}

echo "dovecot -c ${CONFPATH} stop" >> "${TRAVISDIR}/imap-stop.sh"

done

exit 0
