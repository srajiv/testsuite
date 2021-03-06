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
 *	Tspi_Context_FreeMemory01.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_Context_FreeMemory
 *		returns TSS_SUCCESS.
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
 *			   -v or --version
 *	Second parameter is the version of the test case to be run
 *	This test case is currently only implemented for v1.1
 *
 * HISTORY
 *	Megan Schneider, mschnei@us.ibm.com, 6/04.
 *	Kent Yoder, shpedoikal@gmail.com, 1/05
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
	char			version;

	version = parseArgs( argc, argv );
	if (version)
		main_v1_1();
	else
		print_wrongVersion();
}


int
main_v1_1( void )
{
	char			*function = "Tspi_Context_FreeMemory01";
	BYTE			*random;
	TSS_HCONTEXT		hContext, hTPM;
	TSS_RESULT		result;

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
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// Retrieve TPM object of context
	result = Tspi_Context_GetTpmObject( hContext, &hTPM );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_GetTpmObject", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// get a random number to free
	result = Tspi_TPM_GetRandom( hTPM, 16, &random );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_TPM_GetRandom", result );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// Free selected memory
	result = Tspi_Context_FreeMemory( hContext, random );
	if ( result != TSS_SUCCESS )
	{
		if( !(checkNonAPI(result)) )
		{
			print_error( function, result );
		}
		else
		{
			print_error_nonapi( function, result );
		}
	}
	else
	{
		print_success( function, result );
	}

	print_end_test( function );
	Tspi_Context_Close( hContext );
	exit( result );
}
