/*
 *
 *   Copyright (C) International Business Machines  Corp., 2004
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
 *	hlcleanup.c
 *
 * DESCRIPTION
 *	This function will unregister the keys associated
 *		with the common UUIDs.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		(the following code repeats for the keys)
 *		Unregister Key
 *		(end of repeating code)
 *
 *	Test:
 *		None. This is a common cleanup function for
 *		higher-level testcases.
 *
 *	Cleanup:
 *		Print errno log and/or timing stats if options given
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
#include <tss/tss.h>
#include "hlsetup.h"

extern TSS_UUID SRK_UUID;

int
main( int argc, char **argv )
{
	char		*version;

	version = parseArgs( argc, argv );
		// if it is not version 1.1, print error
	if( strcmp(version, "1.1") )
		print_wrongVersion();
	else
		main_v1_1();
}

int
main_v1_1( void )
{
	char		*function = "hlcleanup";
	TSS_HCONTEXT    hContext;
	TSS_HKEY	hKey;
	TSS_RESULT	result;
	UINT32		exitCode = 0;	//initialize to clean exit code

	print_begin_test( function );

		// Create Context
	result = Tspi_Context_Create( &hContext );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Create", result );
		print_error_exit( function, err_string(result) );
		exit( result );
	}

		// Connect to Context
	result = Tspi_Context_Connect( hContext, NULL );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Connect", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM, uuid9,
					&hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_UnregisterKey (9)", result );
		exitCode = 1;
	}
	else
		print_success( "Tspi_Context_UnregisterKey (9)", result );

	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM, uuid8,
					&hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_UnregisterKey (8)", result );
		exitCode = 1;
	}
	else
		print_success( "Tspi_Context_UnregisterKey (8)", result );

	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM, uuid7,
					&hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_UnregisterKey (7)", result );
		exitCode = 1;
	}
	else
		print_success( "Tspi_Context_UnregisterKey (7)", result );

	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM, uuid6,
					&hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_UnregisterKey (6)", result );
		exitCode = 1;
	}
	else
		print_success( "Tspi_Context_UnregisterKey (6)", result );

	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM, uuid5,
					&hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_UnregisterKey (5)", result );
		exitCode = 1;
	}
	else
		print_success( "Tspi_Context_UnregisterKey (5)", result );

	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM, uuid4,
					&hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_UnregisterKey (4)", result );
		exitCode = 1;
	}
	else
		print_success( "Tspi_Context_UnregisterKey (4)", result );

	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM, uuid3,
					&hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_UnregisterKey (3)", result );
		exitCode = 1;
	}
	else
		print_success( "Tspi_Context_UnregisterKey (3)", result );

	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM, uuid2,
					&hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_UnregisterKey (2)", result );
		exitCode = 1;
	}
	else
		print_success( "Tspi_Context_UnregisterKey (2)", result );

	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM, uuid1,
					&hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_UnregisterKey (1)", result );
		exitCode = 1;
	}
	else
		print_success( "Tspi_Context_UnregisterKey (1)", result );

	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM, uuid0,
					&hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_UnregisterKey (0)", result );
		exitCode = 1;
	}
	else
		print_success( "Tspi_Context_UnregisterKey (0)", result );

	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM, kuuid3,
					&hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_UnregisterKey (k3)", result );
		exitCode = 1;
	}
	else
		print_success( "Tspi_Context_UnregisterKey (k3)", result );

	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM, kuuid2,
					&hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_UnregisterKey (k2)", result );
		exitCode = 1;
	}
	else
		print_success( "Tspi_Context_UnregisterKey (k2)", result );

	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM, kuuid1,
					&hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_UnregisterKey (k1)", result );
		exitCode = 1;
	}
	else
		print_success( "Tspi_Context_UnregisterKey (k1)", result );

	print_success( function, result );
	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( exitCode );
}
