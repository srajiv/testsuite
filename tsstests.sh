#!/bin/sh
##
#
#   Copyright (C) International Business Machines  Corp., 2004
#
#   This program is free software;  you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY;  without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
#   the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program;  if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
#
# NAME
#      tsstests.sh
#
# DESCRIPTION
#      This is a simple bash script to run all tests in the ltp-tss/tcg
#		subdirectories.
#
# ALGORITHM
#      None.
#
# USAGE
#      ./tsstests.sh [-v version] [-l logfile]
#	-v  version of the tss spec to use
#	-l  logfile to redirect output to
#
# HISTORY
#      Megan Schneider, mschnei@us.ibm.com, 6/04.
#
# RESTRICTIONS
#      None.
##

export TSS_VERSION=1.1
LOGDIR=$PWD
export LOGFILE=$LOGDIR/tsstests.log
LOGGING=0
PASSFAIL=0
PASSED=0
FAILED=0
SEGFAULTED=0
PRETENDING=0
QUIET=0
export ERR_SUMMARY=../../err.summary

# this variable needs to be changed to testcases/tcg/ for ltp compatibility
TESTCASEDIR=ltp-tss/tcg/

cd ..

export LTPTSSROOT=$PWD

cd $TESTCASEDIR

if [ x${1} != x ]; then
	DIRS_TO_RUN=${1}
else
	DIRS_TO_RUN=`ls */Makefile | sed "s/Makefile//g" | sed "s/common\///g" | sed "s/highlevel\///g" | grep -v sctp`
fi

usage()
{
	cat <<-END >&2
	usage: ./tsstests.sh [-v <version>] [-l <logfile>] [-ph]
		This script will run all tspi-related tests.
		-v	version of the TSS spec to use
		-l	logfile to redirect output to (default is command line)
		-p	check that the test cases can be run, but do not actually run them
		-h	display this help
		-q	run quietly - display only total number of tests passed/failed
	END
	exit
}


# this is to make sure all test cases being run are current, and that make has
# been done in all directories. this part will probably be removed later.
#echo "<<< Compiling all test cases >>>"
#for i in $DIRS_TO_RUN;
#	do
#		echo $i;
#		cd $LTPTSSROOT/$TESTCASEDIR/$i;
#		make;
#	make install;
#	done
#echo "<<< Done compiling >>>"

while getopts v:l:phq arg
do
	case $arg in
		v)	export TSS_VERSION=$OPTARG;;
		l)	export LOGFILE="$LOGDIR/"$OPTARG""
			let LOGGING=1
			`touch ${LOGFILE}`
			cat /dev/null > $LOGFILE;;
		p)	echo "Checking setup for testcases; not running.."
			let PRETENDING=1;;
		h)	usage;;
		q)	let QUIET=1;;
		e)	export ERR_SUMMARY=$OPTARG
	esac
done
shift `let OPTIND-=1`

/bin/rm -f $ERR_SUMMARY

#if [ $QUIET -eq 0 ]; then
#	ps -ef | grep tcsd | grep -v grep
#	if [ $? -eq 1 ]; then
#		echo "tscd not running. Please run '/usr/local/bin/tcsd &' as root."
#		exit 1
#	else
#		echo "tscd running."
#	fi
#else
#	ps -ef | grep tcsd | grep -v grep &> /dev/null
#	if [ $? -eq 1 ]; then
#		echo "tscd not running. Please run '/usr/local/bin/tcsd &' as root."
#		exit 1
#	fi
#fi

echo

#if [ $QUIET -eq 0 ]; then
#	lsmod | grep tpm
#	if [ $? -eq 1 ]; then
#		echo "TPM module not loaded. Please run 'modprobe tpm' as root."
#		exit 1
#	else
#		echo "TPM module loaded."
#	fi
#else
#	lsmod | grep tpm &> /dev/null
#	if [ $? -eq 1 ]; then
#		echo "TPM module not loaded. Please run 'modprobe tpm' as root."
#		exit 1
#	fi
#fi

echo

if [ $PRETENDING -ne 0 ]; then
	echo "Requirements for running testcases met."
else
#	if [ $QUIET -eq 0 ]; then
#		echo "<<< Running all test cases >>>"
#	fi
#
	for i in $DIRS_TO_RUN;
		do
			if [ $QUIET -eq 0 ]; then
				echo $i;
			fi
			if [ $QUIET -eq 0 ]; then
				cd ${LTPTSSROOT}/${TESTCASEDIR}/$i;
			else
				cd ${LTPTSSROOT}/${TESTCASEDIR}/$i &> /dev/null;
			fi
				FILES_TO_RUN=`ls *.c | sed "s/\.c//g"`;
			if [ $QUIET -eq 0 ]; then
				cd ../../bin
			else
				cd ../../bin &> /dev/null;
			fi
			for e in ${FILES_TO_RUN};
			do
				if [ $LOGGING -eq 0 ]; then
					if [ $QUIET -eq 0 ]; then
						{
							./$e -v ${TSS_VERSION}
							RUNRESULT=$?
						} 2>> "$ERR_SUMMARY"
					else
						{
							./$e -v ${TSS_VERSION}
							RUNRESULT=$?
						} &> /dev/null
					fi
				else
					if [ $QUIET -eq 0 ]; then
						{
							./$e -v ${TSS_VERSION}
							RUNRESULT=$?
						} >> "$LOGFILE" 2>> "$ERR_SUMMARY"
					else
						{
							./$e -v ${TSS_VERSION}
							RUNRESULT=$?
						} &> /dev/null
					fi
				fi
				if [ $QUIET -eq 0 ]; then
					if [ $LOGGING -eq 0 ]; then
						echo RESULT: $RUNRESULT
					else
						echo RESULT: $RUNRESULT >> $LOGFILE
					fi
				fi
				if [ $RUNRESULT -ne "0" ]; then
					PASSFAIL=1;
					let FAILED+=1;
					if [ $RUNRESULT -gt "127" ]; then
						let SEGFAULTED+=1;
					fi
				else
					let PASSED+=1;
				fi
				if [ $QUIET -eq 0 ]; then
					if [ $LOGGING -eq 0 ]; then
						echo PASSED: $PASSED
						echo FAILED: $FAILED
						echo SEGFAULTED: $SEGFAULTED
					else
						{
						echo PASSED: $PASSED
						echo FAILED: $FAILED
						echo SEGFAULTED: $SEGFAULTED
						} >> "$LOGFILE"
					fi
				fi
			done
		done
	if [ $QUIET -eq 0 ]; then
		echo "<<< Test case run completed >>>"
	fi

	if [ $PASSFAIL -eq "0" ]; then
		if [ $LOGGING -eq 0 ]; then
			echo Passed Testcases: $PASSED
			echo Failed Testcases: $FAILED
			echo TSStests reported PASS
		else
			echo Passed Testcases: $PASSED >> $LOGFILE
			echo Failed Testcases: $FAILED >> $LOGFILE
			echo TSStests reported PASS >> $LOGFILE
		fi
	else
		if [ $LOGGING -eq 0 ]; then
			echo Passed Testcases: $PASSED
			echo Failed Testcases: $FAILED
			echo Segfaulted: $SEGFAULTED
			echo TSStests reported FAIL
		else
			echo Passed Testcases: $PASSED >> $LOGFILE
			echo Failed Testcases: $FAILED >> $LOGFILE
			echo Segfaulted: $SEGFAULTED >> $LOGFILE
			echo TSStests reported FAIL >> $LOGFILE
		fi
	fi
fi

