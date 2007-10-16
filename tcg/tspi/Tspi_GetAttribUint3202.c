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
 *	Tspi_GetAttribUint3202.c
 *
 * DESCRIPTION
 *	This test will return TSS_E_INVALID_HANDLE, because
 *		whParentKey=-1 is passed as the first parameter
 *		to both Tspi_GetAttribUint32 calls.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *
 *	Test:
 *		Call Tspi_GetAttribUint32 twice then if it does not succeed
 *		Make sure that it returns the proper return codes
 *		Print results
 *
 *	Cleanup:
 *		Free memory related to hContext
 *		Close context
 *
 * USAGE
 *      First parameter is --options
 *                         -v or --version
 *      Second parameter is the version of the test case to be run
 *      This test case is currently only implemented for v1.1
 *
 * HISTORY
 *      Megan Schneider, mschnei@us.ibm.com, 6/04.
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
	char			*function = "Tspi_GetAttribUint3202";
	TSS_HKEY		whParentKey = -1;
	TSS_HKEY		hSRK;
	TSS_HCONTEXT		hContext;
	UINT32			ES;
	UINT32			SS;
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

                // Connect to Context
        result = Tspi_Context_Connect( hContext, get_server(GLOBALSERVER) );
        if ( result != TSS_SUCCESS )
        {
                print_error( "Tspi_Context_Connect", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
                exit( result );
        }

		// Set uint, no encryption, key enc scheme
	result = Tspi_GetAttribUint32( whParentKey,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					&ES );
	if ( TSS_ERROR_CODE(result) != TSS_E_INVALID_HANDLE )
	{
		if( !(checkNonAPI(result)) )
		{
			print_error( function, result );
		}
		else
		{
			print_error_nonapi( function, result );
		}
		exitCode = result;
	}
	else
	{
		print_success( function, result );
		exitCode = 0;
	}

		// Set uint, key sig scheme
	result = Tspi_GetAttribUint32( whParentKey,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
					&SS );
	if ( TSS_ERROR_CODE(result) != TSS_E_INVALID_HANDLE )
	{
		if( !(checkNonAPI(result)) )
		{
			print_error( function, result );
		}
		else
		{
			print_error_nonapi( function, result );
		}
		/* must indicate failure to the shell, even if result == TSS_SUCCESS */
		exitCode = 1;
	}
	else
	{
		print_success( function, result );
	}

	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( exitCode );
}
