#!/bin/sh -e
#
# ### This is a script to setup an exim smtp server for testing rlm_smtp
#

#
# Declare the important path variables
#

# Base Directories
BASEDIR=$(git rev-parse --show-toplevel)
BUILDDIR="${BASEDIR}/build/ci/exim4"

# Directories for exim processes
RUNDIR="${BUILDDIR}/run"
MAILDIR="${BUILDDIR}/mail"
LOGDIR="${BUILDDIR}/eximlog"
SPOOLDIR="${BUILDDIR}/spool"
CERTDIR="${BUILDDIR}/certs"

# Important files for running dovecot
CONF="${BUILDDIR}/exim.conf"

# Used for supporting files
TRAVISDIR="${BASEDIR}/scripts/travis"

#
# Prepare the directories and files needed for running exim
#

# Stop any currently running exim instance
if [ -e "${RUNDIR}/exim.pid" ]
then
	echo "Stopping the current exim instance"
	kill "$(cat ${RUNDIR}/exim.pid)"
	rm -r "${BUILDDIR}"
fi

# Create the directories
mkdir -p "${BUILDDIR}"
mkdir -p "${RUNDIR}"
mkdir -p "${MAILDIR}"
mkdir -p "${LOGDIR}"
mkdir -p "${SPOOLDIR}"
mkdir -p "${CERTDIR}"

# Create the certificate
openssl req -nodes -x509 -newkey rsa:4096 -keyout ${CERTDIR}/selfkey.pem -out ${CERTDIR}/selfcert.pem -days 365 -config ${TRAVISDIR}/exim/cert.cnf

# Create exim.conf file
touch "${CONF}"

# Build exim.conf
echo "
#
# Set the user to run as - use -DEXIMUSER=user -DEXIMGROUP=group
# rather than defining them here.
#
#EXIMUSER = username
#EXIMGROUP = groupname
LISTEN=127.0.0.1
#
#
#  Where all the config files, logs, etc are. See also the
#  "keep_environment" setting below.
#
MAIL_DIR = ${MAILDIR}
pid_file_path = ${RUNDIR}/exim.pid
log_file_path = ${LOGDIR}/%s
spool_directory = ${SPOOLDIR}
exim_user = EXIMUSER
exim_group = EXIMGROUP
daemon_smtp_ports = 2525 : 2465
local_interfaces = LISTEN
deliver_drop_privilege
keep_environment = ${BASEDIR}
tls_advertise_hosts = *
tls_certificate = ${CERTDIR}/selfcert.pem
tls_privatekey = ${CERTDIR}/selfkey.pem
tls_verify_certificates = ${CERTDIR}/selfcert.pem
#tls_dhparam = ${CERTDIR}/dh
tls_on_connect_ports = 2465
tls_verify_hosts = *
tls_require_ciphers = \${if =={\$received_port}{2525}\
                           {NORMAL:%COMPAT}\
                           {SECURE128}}
received_header_text =
acl_smtp_rcpt = accept
begin acl
begin routers
#
#  Only one router - we'll send everything to the \"local_delivery\"
#  transport.
#
local_delivery:
  driver = accept
  transport = local_delivery
  no_more
begin transports
#
# Transport to write a file - this will write mail to an mbox.
#
local_delivery:
  driver = appendfile
  create_directory
  directory_mode = 0750
  mode = 0600
#
#  File to write to. Really dangerous in a normal config as it'll
#  accept anything, including ../whatever, but we're writing our
#  own headers so it doesn't matter so much here.
#
  file = \${if eq {\$h_x-testname:}{} {MAIL_DIR/\$local_part}{MAIL_DIR/\$h_x-testname:}}
begin rewrite
begin retry
*                *                F,1s,1m
begin authenticators

" >"${CONF}"

# Generate a file for test email attachments
dd if=/dev/urandom bs=200 count=1 2>/dev/null | base64 | tr -d '\n'> ${BUILDDIR}/testfile

#
# Run the exim instance
#
exim -C ${CONF} -bd -DEXIMUSER=$(id -u) -DEXIMGROUP=$(id -g)
echo "Running exim on port 2525, accepting all local connections"
