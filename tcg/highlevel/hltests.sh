#!/bin/bash
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
#      hltests.sh
#
# DESCRIPTION
#      This is a simple bash script to run all high-level tests.
#
# ALGORITHM
#      None.
#
# USAGE
#      ./hltests.sh
#	Takes no arguments.
#
# HISTORY
#      Megan Schneider, mschnei@us.ibm.com, 6/04.
#
# RESTRICTIONS
#      None.
##

PASSFAIL=0
PASSED=0
FAILED=0

export HLTSSROOT=$PWD

#usage()
#{
#	cat <<-END >&2
#	usage: ./tsstests.sh
#		This script will run all tspi-related tests.
#		This script takes no arguments.
#	END
#	exit
#}


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

echo "<<< Running high level test cases >>>"
	FILES_TO_RUN=`ls *.c | sed "s/\hlsetup.c//g" | sed "s/\hlcleanup.c//g" | sed "s/\.c//g"`;
#	./hlsetup -v 1.1
	for e in $FILES_TO_RUN;
		do
			./$e -v 1.1;
			RUNRESULT=$?
			if [ $RUNRESULT -ne "0" ]; then
				PASSFAIL=1;
				let FAILED+=1;
			else
				let PASSED+=1;
			fi
		done
	./hlcleanup -v 1.1
echo "<<< Test case run completed >>>"

if [ $PASSFAIL -eq "0" ]; then
	echo Number of Failed Testcases: $FAILED
	echo Number of Passed Testcases: $PASSED
	echo TSStests reported PASS
else
	echo Number of Failed Testcases: $FAILED
	echo Number of Passed Testcases: $PASSED
	echo HLtests reported FAIL
fi

