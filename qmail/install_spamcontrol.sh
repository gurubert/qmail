#!/bin/sh
#
# (UN)INSTALL Script (install_spamcontrol.sh)
# -----------------------------------
#
# Purpose:      To install and uninstall the spamcontrol patch
#
# Parameters:   -u (uninstall)
#	        VRF (Version to be uninstalled)
#
# Usage:        ./install_spamcontrol.sh [-u] [Version]
#
#		Installation: 	./install_spamcontrol.sh
# 		Uninstallation: ./install_spamcontrol.sh -u 105
#
# Return Codes: 0 - Patches applied successfully
#		1 - Original QMAIL files not found (Patch not extracted in QMAIL source directory)
#		2 - Patch files not found 
#		100 - other error
#
# Output:	spamcontrol.log
#
# History:      1.0.0 - Erwin Hoffmann - Initial release
#		1.0.1 - Erwin Hoffmann - Some more verbose information
#		1.0.3 - Erwin Hoffmann - REL=103, removed "cp" in some output line
#		1.0.4 - Erwin Hoffmann - REL=104, small bug fixed
#		1.0.5 - Erwin Hoffmann - REL=105
#		1.0.6 - Erwin Hoffmann - REL=106, Uninstallation added
#		1.0.7 - Erwin Hoffmann - REL=107, Flag for Solaris added
#		1.0.8 - Erwin Hoffmann - REL=108, Patch for ipme.c included
#		1.0.9 - Erwin Hoffmann - REL=109, Copy Documents to ./qmail/docs
#		1.0.10 - Erwin Hoffmann - REL=110, Mods for uninstalling ipme.c patch
#		1.0.11 - Erwin Hoffmann - REL=111, Additional STDOUT listing
#		1.0.12 - Erwin Hoffmann - REL=111, Fixed problem with obsolete "2" while piping to tee
#		1.0.13 - Erwin Hoffmann - REL=111, minor corrections
#		1.1.0 - Erwin Hoffmann - REL=190, patch files read from file FILES.spamcontrol
#		1.1.1 - Erwin Hoffmann - REL=191, misc. files copied to /var/qmail/doc/
#						  identification for SOLARIS included
#		1.1.2 - Erwin Hoffmann - REL=192, fixed typo "find-systype.sh"
#		1.2.0 - Erwin Hoffmann - REL=203  for SPAMCONTROL V2 
#		1.3.0 - Erwin Hoffmann - REL=203  for SPAMCONTROL 2.0.4
#		1.3.1 - Erwin Hoffmann - REL=204  for SPAMCONTROL 2.1.0; STDTERR for patch written to log
#		1.3.2 - Erwin Hoffmann - REL=204  for SPAMCONTROL 2.1.2
#		1.4.0 - Erwin Hoffmann - REL=213  for SPAMCONTROL 2.1.3 - include Build info
#		1.4.1 - Erwin Hoffmann - REL=213  for SPAMCONTROL 2.1.8 - include some exceptions
#		1.4.2 - Erwin Hoffmann - REL=220  for SPAMCONTROL 2.2.0 - include qmail-*2recipients scripts
#		1.4.3 - Erwin Hoffmann - REL=220  for SPAMCONTROL 2.2.4 - BIGTODO trailer
#		1.5.0 - Erwin Hoffmann - REL=225  for SPAMCONTROL 2.2.5 - modifications even for own *.c files
#		1.6.0 - Erwin Hoffmann - REL=225  for SPAMCONTROL 2.2.7 - add test for QMAIL/doc
#		1.6.1 - Erwin Hoffmann - REL=228  for SPAMCONTROL 2.2.8 - rm *.opt now during de-install
#		1.6.2 - Erwin Hoffmann - REL=234  for SPAMCONTROL 2.3.4 
#		1.6.3 - Erwin Hoffmann - REL=234  for SPAMCONTROL 2.3.5 
#		1.6.4 - Erwin Hoffmann - REL=234  for SPAMCONTROL 2.3.6 
#		1.7.0 - Erwin Hoffmann - REL=234  for SPAMCONTROL 2.3.7 - /var/qmail/scripts included 
#		1.8.0 - Erwin Hoffmann - REL=234  for SPAMCONTROL 2.3.9 - removed EXCEPTION
#		1.8.1 -							automated build
#		1.9.0 - Erwin Hoffmann - REL=25x  for SPAMCONTROL 2.5.x - added skeleton directory
#		1.9.1 - Erwin Hoffmann - REL=25x  for SPAMCONTROL 2.5.x - fixed errors
#		1.9.2 - Erwin Hoffmann - REL=25x  for SPAMCONTROL 2.5.x - optimized
#		2.0.0 - Erwin Hoffmann - REL=26x  for SPAMCONTROL 2.6.x - required
#		2.0.1 - Erwin Hoffmann - REL=26x  for SPAMCONTROL 2.6.x - added backup capability for 1.x
#		2.0.2 - Erwin Hoffmann - REL=26x  for SPAMCONTROL 2.6.x - conf-djbdns support added
#		2.0.3 - Erwin Hoffmann - REL=26x  for SPAMCONTROL 2.6.x - removing new files
#		2.0.4 - Erwin Hoffmann - REL=26x  for SPAMCONTROL 2.6.x - changes for djbdns
#
#---------------------------------------------------------------------------------------
#
DATE=$(date)
LOCDIR=${PWD}
QMAILHOME=$(head -n 1 conf-qmail)
UCSPISSLHOME=$(head -n 1 conf-ucspissl)
SOLARIS=$(sh ./find-systype.sh | grep -ci "SunOS")
LOGFILE=spamcontrol.log
TARGETS=FILES.spamcontrol
CONF=conf-spamcontrol
IFSKEEP=${IFS}
REL=2728a # Should be identical to spamcontrol level
BUILD=20130913103408
MYWON=""
MYOWN="${MYOWN}$(grep "^+" FILES.spamcontrol)"
MYOWN="${MYOWN}$(grep "^&" FILES.spamcontrol)"
MYOWN="${MYOWN}$(grep "^%" FILES.spamcontrol)"
MYOWN="${MYOWN}$(grep "^?" FILES.spamcontrol)"
UCSPI="$(grep "^:" FILES.spamcontrol | cut -d':' -f2)"
BACKUPDIR="${PWD}/.spamcontrol-${REL}"

if [ $# -eq 0 ] ; then

	echo "INSTALLING spamcontrol $REL (Build $BUILD) at $DATE <<<" | tee -a $LOGFILE 2>&1 
	rm -f *.opt 2>&1 >> /dev/null
	echo "Original source files will be copied to $BACKUPDIR."
	mkdir -p "$BACKUPDIR" 2>/dev/null || echo "Can't create backup dir. Exit." 
	if [ ! -d "$BACKUPDIR" ]; then
		echo "Can't create backup dir. Exit." 
		exit 100
	fi

	for FILE in $(grep "^= " ${TARGETS} | awk '{print $2}'); do
		echo "Targeting file $FILE ..." | tee -a $LOGFILE 2>&1
		if [ -s ${FILE} ] ; then
			cp -pf ${FILE} ${BACKUPDIR}/${FILE} | tee -a $LOGFILE 2>&1
			echo "--> ${FILE} copied to ${BACKUPDIR}/${FILE}" | tee -a $LOGFILE 2>&1
		else
			echo "${FILE} not found!"
			exit 1
		fi
		if [ -s ${FILE}.patch ] ; then
			if [ ${SOLARIS} -gt 0 ]; then
				echo "--> Patching qmail source file ${FILE} for Solaris ...." | tee -a $LOGFILE 2>&1
				patch -i ${FILE}.patch ${FILE} 2>&1 | tee -a $LOGFILE
			else
				echo "--> Patching qmail source file ${FILE}  ...." | tee -a $LOGFILE 2>&1
				patch ${FILE} ${FILE}.patch 2>&1 | tee -a $LOGFILE
			fi
		else
			echo "!! ${FILE}.patch not found / not applicable !"
			exit 2
		fi
	done 

	echo "Adjusting compile options as defined in ${CONF} ..." | tee -a $LOGFILE 2>&1 
	rm sedfile 2>/dev/null

	for FILE in $(cat ${TARGETS} | grep "\.c" | grep -v "^%" | awk '{print $2}'); do
	        IFS=' =#'
		echo "--> Modifying compile time options for ${FILE}  ...." | tee -a $LOGFILE 2>&1
        	while read OPTION FLAG REST
       		do
			if [ $(echo "${FLAG}" | grep -i "^no") ]; then
				CHANGE=$(grep -i "^#define ${OPTION}" ${FILE} | head -n 1)
				if [ "x${CHANGE}" != "x" ]; then
					echo "s-^${CHANGE}-/\* ${CHANGE} \*/-" >> sedfile 
				fi
				if [ -f sedfile ]; then
					sed -f sedfile ${FILE} > ${FILE}.opt
					cp ${FILE}.opt ${FILE}
				fi
			fi
		done < ${CONF}
		IFS=${IFSKEEP}
	done

	for FILE in $(grep "^+ " ${TARGETS} | awk '{print $2}'); do
	        IFS=' =#'
		echo "--> Modifying compile time options for ${FILE}  ...." | tee -a $LOGFILE 2>&1
        	while read OPTION FLAG REST
       		do
			if [ $(echo "${FLAG}" | grep -i "^no") ]; then
				CHANGE=$(grep -i "^#define ${OPTION}" ${FILE} | head -n 1)
				if [ "x${CHANGE}" != "x" ]; then
					echo "s-^${CHANGE}-/\* ${CHANGE} \*/-" >> sedfile 
				fi
				if [ -f sedfile ]; then
					sed -f sedfile ${FILE} > ${FILE}.opt
					cp ${FILE}.opt ${FILE}
				fi
			fi
		done < ${CONF}
		IFS=${IFSKEEP}
	done


	if [ -f conf-djbdns ]; then
		if [ -f $(head -1 conf-djbdns) ]; then
			DNSLIB=$(head -1 conf-djbdns)
			if [ -f ${DNSLIB} ]; then
				echo "Adjusting DNS resolver library $DNSLIB ..." | tee -a $LOGFILE 2>&1

				sed s%\error.a\ dns.o\ \`cat\ dns.lib\`%\ "$DNSLIB"%g Makefile > Makefile.opt
				cp Makefile.opt Makefile
			else
				echo "Warning: you did not build qmail.a in the djbdns-1.05 ! (README.djbdns)"
			fi
		fi
	fi

	echo "Copying additional scripts to ${QMAILHOME}/scripts/ ..." | tee -a $LOGFILE 2>&1 

	if [ ! -d ${QMAILHOME}/scripts ] ; then
		echo "Creating ${QMAILHOME}/scripts ..."
		mkdir ${QMAILHOME}/scripts
		if [ $? -ne 0 ]; then
			echo "You are not executing the installation script as 'root'."
			echo "That's ok. However, you will miss the installation of documentation and scripts."
			echo "Simply continue and check the installation log afterwards for the missing pieces."
			echo "Type 'exit' if you wish to continue as root."
			read REPLY
			if [ "$REPLY" = "exit" ]; then
        			exit
			else
			        echo "Proceeding with spamcontrol $REL installation .."
			fi
		fi
	fi

	echo "Attention!!" | tee -a $LOGFILE 2>&1

	for FILE in $(grep "^& " ${TARGETS} | awk '{print $2}'); do
		cp ${FILE} ${QMAILHOME}/scripts/ | tee -a $LOGFILE 2>&1
		chmod +x ${QMAILHOME}/scripts/${FILE}
		chown root:qmail ${QMAILHOME}/scripts/${FILE}
		ls -la ${QMAILHOME}/scripts/${FILE} | tee -a $LOGFILE 2>&1
	done
	echo "These scripts need to be customized for your environment!" | tee -a $LOGFILE 2>&1

	echo "Copying documentation and samples to ${QMAILHOME}/doc/ ..." | tee -a $LOGFILE 2>&1 

	if [ ! -d ${QMAILHOME}/doc ] ; then
		echo "Creating ${QMAILHOME}/doc ..."
		mkdir ${QMAILHOME}/doc
		chown root:qmail ${QMAILHOME}/doc/
	fi
	for FILE in $(grep "^% " ${TARGETS} | awk '{print $2}'); do
		cp ${FILE} ${QMAILHOME}/doc/ | tee -a $LOGFILE 2>&1
		ls -la ${QMAILHOME}/doc/${FILE} | tee -a $LOGFILE 2>&1
	done

	echo "Copying skeleton run-files to ${QMAILHOME}/skeleton/ ..." | tee -a $LOGFILE 2>&1 

	if [ ! -d ${QMAILHOME}/skeleton ] ; then
		echo "Creating ${QMAILHOME}/skeleton ..."
		mkdir ${QMAILHOME}/skeleton
		chown root:qmail ${QMAILHOME}/skeleton/
	fi

	echo "Creating source directory for QMQ at: ${QMAILHOME}/source/ ..." | tee -a $LOGFILE 2>&1 

	if [ ! -d ${QMAILHOME}/source ] ; then
		echo "Creating ${QMAILHOME}/source and copying current qmail files here ..."
		mkdir ${QMAILHOME}/source 
		for FILE in $(ls | grep -v "${MYOWN}"); do
			cp -p ${FILE} ${QMAILHOME}/source/
		done
	fi
	for FILE in $(grep "^% " FILES.spamcontrol | awk '{print $2}' | grep run); do
		cp ${FILE} ${QMAILHOME}/skeleton/ | tee -a $LOGFILE 2>&1
		ls -la ${QMAILHOME}/skeleton/${FILE} | tee -a $LOGFILE 2>&1
	done

	echo "Setting up SPAMCONTROL for STARTTLS support in qmail-remote ..."  | tee -a $LOGFILE 2>&1
	echo " ... this requires 'conf-ucspissl' ($UCSPISSLHOME) and this package compiled in advance."  | tee -a $LOGFILE 2>&1

	if [ -d $UCSPISSLHOME ]; then
		for FILE in ${UCSPI}; do
			if [ -f $UCSPISSLHOME/$FILE ]; then
				cp $UCSPISSLHOME/$FILE . && echo "File $FILE copied succesful."
			else 
				echo "Missing UCSPI-SSL file: $FILE."
		  		exit 100
			fi
		done
	fi	

	echo "INSTALLATION of spamcontrol $REL (Build $BUILD) finished at $DATE <<<" | tee -a $LOGFILE 2>&1 

# Now go for the uninstallation....

elif [ "$1" = "-u" ] ; then

# Get the Version Number from INPUT 

	if [ $# -eq 2 ] ; then
		if [ $2 -gt 100 ] ; then
			REL=$2
			BACKUPDIR="${PWD}/.spamcontrol-${2}"
		fi
	fi

	echo "DE-INSTALLING spamcontrol $REL (Build $BUILD) at $DATE <<<" | tee -a $LOGFILE 2>&1 
	rm -f *.opt 2>&1 >> /dev/null

	for FILE in $(grep "^+ " ${TARGETS} | awk '{print $2}'); do
		rm "${FILE}"
		echo "Removing spamcontrol file $FILE  ...:"
	done

	for FILE in $(grep "^& " ${TARGETS} | awk '{print $2}'); do
		rm "${FILE}"
		echo "Removing spamcontrol file $FILE  ...:"
	done

	for FILE in $(grep "^: " ${TARGETS} | awk '{print $2}'); do
		rm "${FILE}"
		echo "Removing spamcontrol file $FILE  ...:"
	done

	for FILE in $(grep "^? " ${TARGETS} | awk '{print $2}'); do
		rm "${FILE}"
		echo "Removing spamcontrol file $FILE  ...:"
	done

	for FILE in $(grep "^= " ${TARGETS} | awk '{print $2}'); do
		echo "Targeting file $FILE ..." | tee -a $LOGFILE 2>&1
		if [ -f ${BACKUPDIR}/${FILE} ] ; then
			cp -fp ${BACKUPDIR}/${FILE} ${FILE} | tee -a $LOGFILE 2>&1
			echo "--> ${FILE} recovered from ${BACKUPDIR} directory." | tee -a $LOGFILE 2>&1
                elif [ -s ${FILE}.$REL ] ; then
                        mv ${FILE}.${REL} ${FILE} | tee -a $LOGFILE 2>&1
                        touch ${FILE}
                        echo "--> ${FILE}.${REL} moved to ${FILE}" | tee -a $LOGFILE 2>&1

		else
			echo "!! ${FILE} not found in ${BACKUPDIR} directory !!"
		fi
	done
	echo "DE-INSTALLATION of spamcontrol $REL (Build $BUILD) finished at $DATE <<<" | tee -a $LOGFILE 2>&1 
fi

exit 0
