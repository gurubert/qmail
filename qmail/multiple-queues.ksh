#!/usr/local/bin/ksh
#set -o xtrace

QMAIL_HOME=$(head -1 conf-qmail)
QMAIL_LOGS="/var/log"
SVC_HOME="/service"

SKELETON_SOURCE="${QMAIL_HOME}/source"
SKELETON_ME="mail.example.com"
SKELETON_CONCURRENCYREMOTE="120"
SKELETON_QUEUELIFETIME="1440"
SKELETON_PORT="1000"

SKELETON_DIR="${QMAIL_HOME}/skeleton"
SKELETON_QMAIL_SEND="send_run"
SKELETON_QMAIL_SMTP="smtpd_run"
SKELETON_QMAIL_QMTP="qmtpd_run"
SKELETON_QMAIL_LOG="log_run"

if [[ -f conf-qmq ]]; then
	MYINSTANCES=$(grep -v "^#" conf-qmq | cut -d"#" -f1)
	echo "The following qmail instances are defined:"
	echo ""
	grep -v "^#" conf-qmq
	echo ""
	echo "--> Use '$0 build' to setup the instances."
	echo "--> Use '$0 conf' to deploy the instances."
	echo "--> Use '$0 all' to setup and deploy the instances."
	echo ""
	echo "Note (1): qmail will be installed at '${QMAIL_HOME}'." 
	echo "Note (2): qmail-logs will be installed at '${QMAIL_LOGS}/qmail-send-INSTANCEID' ...."
	echo "Note (3): 'service' base directory is '${SVC_HOME}'."
	echo "Note (4): 'qmail-send' will be initially touched 'down' at every instance."
	echo "Note (5): Initial configuration is: 'queuelifetime=${SKELETON_QUEUELIFETIME}', concurrencyremote=${SKELETON_CONCURRENCYREMOTE}'."
	echo "Note (6): Communication from the primary qmail instance to the secondaries is based on 'QMTP'.
	echo ""
	echo "Enter 'ctl-c' to abort; or continue installation."
else
	echo "Configuration file 'conf-qmq' not available."
	exit 1
fi

set -A INSTANCES ${MYINSTANCES}

if [[ "$1" = "build" || "$1" = "all" ]]; then
	for MAPPING in ${INSTANCES[@]}
	do
		INSTANCE=$(echo "${MAPPING}" | awk -F: '{print $1}')
		NAME=$(echo "${MAPPING}" | awk -F: '{print $2}')
		if [[ "x${NAME}" != "x" ]]; then
			mkdir ${QMAIL_HOME}-${INSTANCE}
			mkdir ${QMAL_LOGS}/qmail-${INSTANCE}
			chown qmaill ${QMAL_LOGS}/qmail-${INSTANCE}
			mkdir ${QMAL_LOGS}/qmtp-${INSTANCE}
			chown qmaill ${QMAL_LOGS}/qmtp-${INSTANCE}
			cd ${QMAIL_SOURCE}
			echo "${QMAIL_HOME}-${INSTANCE}" > conf-qmail
			make
			make setup check
			echo "${SKELETON_ME}" > ${QMAIL_HOME}-${INSTANCE}/control/me
			echo "${SKELETON_CONCURRENCYREMOTE}" > ${QMAIL_HOME}-${INSTANCE}/control/concurrencyremote
			echo "${SKELETON_QUEUELIFETIME}" > ${QMAIL_HOME}-${INSTANCE}/control/queuelifetime
		fi
	done
elif [[ "$1" = "conf" || "$1" == "all" ]]; then
	for MAPPING in ${INSTANCES[@]}
	do
		INSTANCE=$(echo "${MAPPING}" | awk -F: '{print $1}')
		NAME=$(echo "${MAPPING}" | awk -F: '{print $2}')
		if [[ "x${NAME}" != "x" ]]; then
			integer PORT=$((${SKELETON_PORT}+${INSTANCE}))
			echo "Selecting ${PORT} for instance ${INSTANCE} ..."
#
## qmail-send/qmail-start
#
			mkdir -p ${QMAIL_HOME}-${INSTANCE}/svc/qmail-${INSTANCE}-send/log
			touch ${QMAIL_HOME}-${INSTANCE}/svc/qmail-${INSTANCE}-send/down

			cp ${SKELETON_QMAIL_LOG} ${QMAIL_HOME}-${INSTANCE}/svc/qmail-${INSTANCE}-send/log/run
			chmod +x ${QMAIL_HOME}-${INSTANCE}/svc/qmail-${INSTANCE}-send/log/run

			sed s/INSTANCE/${INSTANCE}/g ${SKELETON_DIR}/${SKELETON_QMAIL_SEND} > \
				${QMAIL_HOME}-${INSTANCE}/svc/qmail-${INSTANCE}-send/run
			chmod +x ${QMAIL_HOME}-${INSTANCE}/svc/qmail-${INSTANCE}-send/run
			ln -s ${QMAIL_HOME}-${INSTANCE}/svc/qmail-${INSTANCE}-send ${SVC_HOME}/qmail-${INSTANCE}-send
#
## qmail-qmtpd
#
			mkdir -p ${QMAIL_HOME}-${INSTANCE}/svc/qmail-${INSTANCE}-qmtpd/log

			cp ${SKELETON_QMAIL_LOG} ${QMAIL_HOME}-${INSTANCE}/svc/qmail-${INSTANCE}-qmtpd/log/run
			chmod +x ${QMAIL_HOME}-${INSTANCE}/svc/qmail-${INSTANCE}-qmtpd/log/run

			sed s/INSTANCE/${INSTANCE}/g ${SKELETON_DIR}/ ${SKELETON_QMAIL_QMTPD} | \
				sed s/PORT/${PORT}/g > ${QMAIL_HOME}-${INSTANCE}/svc/qmail-${INSTANCE}-qmtpd/run
			chmod +x ${QMAIL_HOME}-${INSTANCE}/svc/qmail-${INSTANCE}-qmtpd/run
#
## link to /service
# 
			ln -s ${QMAIL_HOME}-${INSTANCE}/svc/qmail-${INSTANCE}-qmtpd ${SVC_HOME}/qmail-${INSTANCE}-qmtpd
			ln -s ${QMAIL_HOME}-${INSTANCE}/svc/qmail-${INSTANCE}-start ${SVC_HOME}/qmail-${INSTANCE}-start
		fi
	done
else
	echo "Please provide either 'build' and 'conf' for individual steps; or 'all' for all-inclusive."
fi

exit 0

