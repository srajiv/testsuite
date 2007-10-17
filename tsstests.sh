#!/bin/bash
#
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
#
# HISTORY
#      Megan Schneider, mschnei@us.ibm.com, 6/04.
#      kyoder@users.sf.net, Added shifts to the option processing
#                           Added output format options
#
# RESTRICTIONS
#      None.
##


export TSS_VERSION=1.1
LOGDIR=$PWD
export LOGFILE=$LOGDIR/tsstests.log
LOGGING=0
INIT=0
QUIET=0
export ERR_SUMMARY=../../err.summary
SPECIFIC_TEST_DIR=

TEST_RUN=
TEST_OUTPUT=
OUTPUT_FORMAT="standard"

# this variable needs to be changed to testcases/tcg/ for ltp compatibility
TESTCASEDIR=testsuite/tcg/

cd ..

export LTPTSSROOT=$PWD

cd $TESTCASEDIR

usage()
{
	cat <<-END >&2
	usage: ./tsstests.sh [-v <version>] [-l <logfile>] [-e <errfile>] [-d <dir>] [-h]
		This script will run all tspi-related tests unless the <dir> option is provided.
		-v	 version of the TSS spec to use, 1.1 or 1.2
		-l	 logfile to redirect output to (default is command line)
		-f	 error output format: "wiki" or "standard"
		-h	 display this help
		-q	 run quietly - display only total number of tests passed/failed
		-e	 file name to log errors to
		-d <dir> a specific directory to run tests from (to run a subset of all tests)
	END
	exit -1
}

# Parse the options
while getopts v:l:f:hqd: arg
do
	case $arg in
		v)
			export TSS_VERSION=$OPTARG
			;;
		l)
			if test $QUIET -eq 1; then
				echo "Conflicting args: -q and -l"
				exit -1
			fi
			export LOGFILE="$LOGDIR/"$OPTARG""
			LOGGING=1
			touch $LOGFILE
			;;
		f)
			OUTPUT_FORMAT=$OPTARG
			;;
		h)
			usage
			;;
		q)
			if test $LOGGING -eq 1; then
				echo "Conflicting args: -q and -l"
				exit -1
			fi
			QUIET=1
			;;
		e)
			export ERR_SUMMARY=../../$OPTARG
			;;
		d)
			if test -d ${LTPTSSROOT}/${TESTCASEDIR}/$OPTARG; then
				SPECIFIC_TEST_DIR=$OPTARG
				echo "Only running tests found in ${LTPTSSROOT}/${TESTCASEDIR}/$OPTARG"
			else
				echo "Unknown option: $OPTARG."
				usage
			fi
			;;
		?)
			usage
			;;
	esac
done

#echo "DEBUG DOLLARSTAR: $*"

# Verify the output format
case "$OUTPUT_FORMAT" in
	*standard*)
		echo "Using output format: $OUTPUT_FORMAT"
		;;
	*wiki*)
		echo "Using output format: $OUTPUT_FORMAT"
		;;
	*)
		echo "Unknown format: $OUTPUT_FORMAT"
		usage
		;;
esac

# Print the final total test run info based on output format
# $1 = number passed
# $2 = number failed
# $3 = number not implemented
# $4 = number not applicable
# $5 = number segfaulted
print_totals()
{
	case "$OUTPUT_FORMAT" in
	*standard*)
		echo -e "PASSED: $1\nFAILED: $2 (NOTIMPL: $3)\nNOT APPLICABLE: $4\nSEGFAULTED: $5\n" >> $ERR_SUMMARY
		;;
	*wiki*)
		# Print a new header
		echo "Total Passed | "  >> $ERR_SUMMARY
		echo "  Total Failed |"  >> $ERR_SUMMARY
		echo "    Total Not Implemented |"  >> $ERR_SUMMARY
		echo "      Total Not Applicable |"  >> $ERR_SUMMARY
		echo "        Total segfaulted"  >> $ERR_SUMMARY

		# Print the final info
		echo "$1 | "  >> $ERR_SUMMARY
		echo "  $2 |"  >> $ERR_SUMMARY
		echo "    $3 |"  >> $ERR_SUMMARY
		echo "      $4 |"  >> $ERR_SUMMARY
		echo "        $5"  >> $ERR_SUMMARY
		;;
	*)
		echo "Unknown output format!"
		exit -1
		;;
	esac
}

# Print the final total test run info based on output format
# $1 = Testcase name and version string
# $2 = The stderr from the testcase
# $3 = The return code received from $?
print_error()
{
	case "$OUTPUT_FORMAT" in
	*standard*)
		if test $3 -gt 126; then
			echo "Test segfaulted or returned unknown error (rc=$3): $1" >> $ERR_SUMMARY
		fi
		echo $2 >> $ERR_SUMMARY
		;;
	*wiki*)
		echo "$1 | " >> $ERR_SUMMARY
		echo "  $2 |" >> $ERR_SUMMARY
		echo "    $3 |" >> $ERR_SUMMARY
		if test $3 -gt 126; then
			echo "      (segfault counted as failure) |" >> $ERR_SUMMARY
		else
			echo "      . |" >> $ERR_SUMMARY
		fi
		echo "        ." >> $ERR_SUMMARY
		;;
	*)
		echo "Unknown output format!"
		exit -1
		;;
	esac
}

# Print any initial output based on output format
print_init()
{
	if test $INIT -eq 1; then
		return
	fi

	case "$OUTPUT_FORMAT" in
		*standard*)
			;;
		*wiki*)
			echo "Test Name / Version | " >> $ERR_SUMMARY
			echo "  Test Output |" >> $ERR_SUMMARY
			echo "    Test Return Code |" >> $ERR_SUMMARY
			echo "      . |" >> $ERR_SUMMARY
			echo "        ." >> $ERR_SUMMARY
			;;
		*)
			echo "Unknown output format!"
			exit -1
			;;
	esac

	INIT=1
}


# $1 = the test command line
execute_test()
{
	if test $LOGGING -eq 1; then
		# capture stderr and send stdout to the logfile
		TEST_STDERR=$( $1 -v ${TSS_VERSION} 2>&1 >> $LOGFILE )
	else
		# capture stderr and send stdout to the terminal
		TEST_STDERR=$( $1 -v ${TSS_VERSION} 2>&1 >/dev/tty )
	fi
	RUNRESULT=$?

	if test $RUNRESULT -ne 0; then
		if test $RUNRESULT -gt 126; then
			SEGFAULTED=$(( $SEGFAULTED + 1))
			FAILED=$(( $FAILED + 1));
		elif test $RUNRESULT -eq 126; then
			# 126 is a special number used in testsuite/tcg/common/common.c::print_NA()
			# and is triggered when a testcase is not applicable to the TSS version
			# being tested
			NA=$(( $NA + 1))
		elif test $RUNRESULT -eq 6; then
			NOTIMPL=$(( $NOTIMPL + 1))
		else
			FAILED=$(( $FAILED + 1))
		fi

		print_error "$1 -v ${TSS_VERSION}" "$TEST_STDERR" $RUNRESULT
	else
		if test $LOGGING -eq 1; then
			echo $TEST_STDERR >> $LOGFILE
		else
			echo $TEST_STDERR
		fi
		PASSED=$(( $PASSED + 1))
	fi
}

# main is called at the very end of this script
# $1 = a specific directory to go to run tests
main()
{
	PASSED=0
	FAILED=0
	SEGFAULTED=0
	NOTIMPL=0
	NA=0

	if test x$1 != x; then
		DIRS_TO_RUN=$1
	else
		DIRS_TO_RUN=`ls */Makefile | sed "s/Makefile//g" | sed "s/common\///g" | sed "s/highlevel\///g"`
	fi

	for DIRECTORY in $DIRS_TO_RUN
	do
		TESTS_TO_RUN=

		if test $QUIET -eq 0; then
			echo $DIRECTORY
			cd ${LTPTSSROOT}/${TESTCASEDIR}/$DIRECTORY
			TESTS_TO_RUN=`ls *.c | sed "s/\.c//g"`
			cd ../../bin
		else
			cd ${LTPTSSROOT}/${TESTCASEDIR}/$DIRECTORY &> /dev/null
			TESTS_TO_RUN=`ls *.c | sed "s/\.c//g"`
			cd ../../bin &> /dev/null
		fi

		print_init

		for TEST in $TESTS_TO_RUN
		do
			execute_test ./$TEST

			# Printing totals here is a special case: if you're watching the output
			# roll by (not going to a log file), its good to know a general pass/fail
			# count so you can kill the run if something is obviously wrong
			if test $QUIET -eq 0; then
				if test $LOGGING -eq 0; then
					echo -e "PASSED: $PASSED\nFAILED: $FAILED (NOTIMPL: $NOTIMPL)\nNOT APPLICABLE: $NA\nSEGFAULTED: $SEGFAULTED"
				fi
			fi
		done
	done

	if test $QUIET -eq 0; then
		print_totals $PASSED $FAILED $NOTIMPL $NA $SEGFAULTED
		echo "<<< Test suite run completed >>>"
	fi
}

main $SPECIFIC_TEST_DIR

exit 0

