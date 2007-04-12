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
 *	Tspi_TPM_GetCapability04.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_TPM_GetCapability
 *	works correctly when querying the TPM for an algorithm.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Get TPM Object
 *		Set SubCap Info
 *
 *	Test:
 *		Call TPM_GetCapability then if it does not succeed
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
	char			*function = "Tspi_TPM_GetCapability04";
	UINT32			pulRespDataLength;
	BYTE			*pAlgSupported;
	UINT32			subCap, subCapLength, numPcrs;
	TSS_HCONTEXT		hContext;
	TSS_HTPM		hTPM;
	TSS_RESULT		result;

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
	result = Tspi_Context_Connect( hContext, get_server(GLOBALSERVER) );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Connect", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// Retrieve TPM object of context
	result = Tspi_Context_GetTpmObject( hContext, &hTPM );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_GetTpmObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	subCap = TSS_ALG_RSA;
	subCapLength = sizeof(UINT32);

	result = Tspi_TPM_GetCapability( hTPM, TSS_TPMCAP_ALG,
					 subCapLength, (BYTE *)&subCap,
					 &pulRespDataLength,
					 &pAlgSupported );
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
		/* If the TPM reports that it doesn't support RSA, treat that as an error. All
		 * TPMs should support RSA */
		if (pulRespDataLength == sizeof(BYTE)) {
			if (*(BYTE *)pAlgSupported)
				print_success( function, result );
			else {
				print_error( function, result );
				result = 1; // report error to shell
			}
		} else if (pulRespDataLength = sizeof(UINT32)) {
			if (*(UINT32 *)pAlgSupported)
				print_success( function, result );
			else {
				print_error( function, result );
				result = 1; // report error to shell
			}
		} else {
			/* If the TSP returns a size other than a BYTE (to represent a BOOL) or
			 * a UINT32, consider that an error, too. Apps shouldn't have to check
			 * more than 2 sizes. */
			fprintf(stderr, "\tSize of returned data was %u\n", pulRespDataLength);
			print_error( function, result );
			result = 1; // report error to shell
		}
	}

	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( result );
}
