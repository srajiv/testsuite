/*
 *
 *   Copyright (C) International Business Machines  Corp., 2004, 2005
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 * NAME
 *	Tspi_GetPolicyObject02.c
 *
 * DESCRIPTION
 *	This test will return TSS_E_INVALID_HANDLE, because
 *		whSRK=-1 is passed in as the handle to the object.
 *
 * ALGORITHM
 *	Setup:
 *
 *	Test:
 *		Call GetPolicyObject then if it does not succeed
 *		Make sure that it returns the proper return codes
 *		Print results
 *
 *	Cleanup:
 *
 * USAGE
 *      First parameter is --options
 *                         -v or --version
 *      Second parameter is the version of the test case to be run
 *      This test case is currently only implemented for v1.1
 *
 * HISTORY
 *      Megan Schneider, mschnei@us.ibm.com, 6/04.
 *      Kent Yoder, kyoder@users.sf.net
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include "common.h"


int
main( int argc, char **argv )
{
	char version;

	version = parseArgs( argc, argv );
	if (version)
		main_v1_1();
	else
		print_wrongVersion();
}

int
main_v1_1( void )
{
	char		*function = "Tspi_GetPolicyObject02";
	TSS_HKEY	whSRK = -1;
	TSS_RESULT	result;
	UINT32		exitCode;
	TSS_HPOLICY	srkUsagePolicy;

	print_begin_test( function );

		//Get Policy Object
	result = Tspi_GetPolicyObject( whSRK, TSS_POLICY_USAGE,
					&srkUsagePolicy );
	if ( TSS_ERROR_CODE(result) != TSS_E_INVALID_HANDLE )
	{
		if( !(checkNonAPI(result)) )
		{
			print_error( function, result );
                        exitCode = 1;
		}
		else
		{
			print_error_nonapi( function, result );
			exitCode = 1;
		}
	}
	else
	{
		print_success( function, result );
		exitCode = 0;
	}

	print_end_test( function );
	exit( exitCode );
}
