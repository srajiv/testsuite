/*
 *
 *   Copyright (C) International Business Machines  Corp., 2007
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
 *	Tspi_TPM_CreateRevocableEndorsementKey01.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_TPM_CreateRevocableEndorsementKey
 *		returns TSS_SUCCESS.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Get TPM Object
 *		Create Object
 *		Set Attrib Uint (twice)
 *
 *	Test:
 *		Call TPM_CreateRevocableEndorsementKey then if it does not succeed
 *		Make sure that it returns the proper return codes
 *		Print results
 *
 *	Cleanup:
 *		Free memory relating to hContext
 *		Close context
 *
 * USAGE
 *      First parameter is --options
 *                         -v or --version
 *      Second parameter is the version of the test case to be run
 *      This test case is currently only implemented for v1.1
 *
 * HISTORY
 *      Tom Lendacky, toml@us.ibm.com, 8/07.
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
	if (version >= TESTSUITE_TEST_TSS_1_2)
		main_v1_2(version);
	else
		print_NA();
}

int
main_v1_2( char version )
{
	char			*function = "Tspi_TPM_CreateRevocableEndorsementKey01";
	TSS_HCONTEXT		hContext;
	TSS_HTPM		hTPM;
	TSS_HKEY		hKey;
	TSS_RESULT		result;
	BYTE			*data;
	TSS_FLAG		initFlags = TSS_KEY_TYPE_SIGNING |
						TSS_KEY_SIZE_2048 |
						TSS_KEY_VOLATILE |
						TSS_KEY_NO_AUTHORIZATION |
						TSS_KEY_NOT_MIGRATABLE;
	BYTE			resetData[TPM_SHA1BASED_NONCE_LEN];
	UINT32			resetAuthSize = sizeof(resetData);
	BYTE			*resetAuth = resetData;
	UINT32			exitCode = 0;

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

		// Create Object
	result = Tspi_Context_CreateObject( hContext,
						TSS_OBJECT_TYPE_RSAKEY,
						initFlags, &hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (hKey)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_SetAttribUint32( hKey, TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					TSS_ES_NONE );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_SetAttribUint32 (enc)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_SetAttribUint32( hKey, TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
					TSS_SS_NONE );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_SetAttribUint32 (sig)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	memset(resetData, 0x01, sizeof(resetData));
	result = Tspi_TPM_CreateRevocableEndorsementKey( hTPM, hKey, NULL,
			&resetAuthSize, &resetAuth);
	if ( TSS_ERROR_CODE(result) != TCPA_E_DISABLED_CMD &&
	     TSS_ERROR_CODE(result) != TCPA_E_FAIL &&
	     result != TSS_SUCCESS )
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
	}

	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( exitCode );
}
