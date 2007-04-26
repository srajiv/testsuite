/*
 *
 *   Copyright (C) International Business Machines  Corp., 2004, 2005, 2007
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
 *	Tspi_PcrComposite_GetCompositeHash03.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_PcrComposite_GetCompositeHash
 *		returns TSS_SUCCESS.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Create PCR Composite
 *
 *	Test:
 *		Call PcrComposite_SetPcrValue then if it does not succeed
 *		Make sure that it returns the proper return codes
 *		Print results
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
 *      Kent Yoder, shpedoikal@gmail.com, 04/2007
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include "common.h"


int
main( int argc, char **argv )
{
	char		version;

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
	char		*function = "Tspi_PcrComposite_GetCompositeHash03";
	TSS_HCONTEXT	hContext;
	TSS_HPCRS	hPcrComposite;
	UINT32		pLen;
	BYTE            *ppbHashData;
	TSS_RESULT	result;

	print_begin_test( function );

		// Create Context
	result = Tspi_Context_Create( &hContext );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Create", result );
		print_error_exit( function, err_string(result) );
		exit( result );
	}

		// Create a 1.1 style PCR_INFO struct
	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_PCRS,
					TSS_PCRS_STRUCT_INFO, &hPcrComposite );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (hPcrComposite)",
				result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_PcrComposite_GetCompositeHash(hPcrComposite, &pLen, &ppbHashData );
	if ( TSS_ERROR_CODE(result) != TSS_E_INVALID_OBJ_ACCESS )
	{
		if( !(checkNonAPI(result)) )
		{
			print_error( function, result );
			print_end_test( function );
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit(result);
		}
		else
		{
			print_error_nonapi( function, result );
			print_end_test( function );
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit(result);
		}
	}
	else
	{
		print_success( function, result );
		print_end_test( function );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( 0 );
	}
}
