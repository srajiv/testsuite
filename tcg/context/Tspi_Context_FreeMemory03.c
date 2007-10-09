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
 *	Tspi_Context_FreeMemory03.c
 *
 * DESCRIPTION
 *	This testcase tests whether Tspi_Context_FreeMemory returns TSS_E_INVALID_RESOURCE
 *	when passed a handle to memory not returned from a TSS API.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *
 *	Test:
 *		Call Context_FreeMemory then if it does not succeed
 *		Make sure that it returns the proper return codes
 *		Print results
 *
 *	Cleanup:
 *		Close context
 *
 * USAGE
 *      First parameter is --options
 *                         -v or --version
 *      Second parameter is the version of the test case to be run
 *      This test case is currently only implemented for v1.1
 *
 * HISTORY
 *	Kent Yoder <kyoder@users.sf.net> 04/2007
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include <stdlib.h>

#include "common.h"


int
main( int argc, char **argv )
{
	char	version;

	version = parseArgs( argc, argv );
	if (version == TESTSUITE_TEST_TSS_1_2)
		main_v1_2(version);
	else if (version == TESTSUITE_TEST_TSS_1_1)
		print_NA();
	else
		print_wrongVersion();
}

int
main_v1_2(char version)
{
	char			*function = "Tspi_Context_FreeMemory03";
	TSS_HCONTEXT		hContext;
	TSS_RESULT		result;
	UINT32			exitCode = 0;

	print_begin_test( function );

		// Create Context
	result = Tspi_Context_Create( &hContext );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Create", result );
		exit( result );
	}

		// Free selected memory
	result = Tspi_Context_FreeMemory( hContext, (PVOID)0xdeadbeef );
	if ( TSS_ERROR_CODE(result) != TSS_E_INVALID_RESOURCE )
	{
		if( !(checkNonAPI(result)) )
		{
			print_error( function, result );
			exitCode = result;
		}
		else
		{
			print_error_nonapi( function, result );
			exitCode = result;
		}
	}
	else
	{
		print_success( function, result );
	}

	print_end_test( function );
	Tspi_Context_Close( hContext );
	exit( exitCode );
}
