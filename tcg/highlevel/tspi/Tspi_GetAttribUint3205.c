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
 *	Tspi_GetAttribUint3205.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_GetAttribUint32 works on the
 *	backported TSS_TSPATTRIB_SECRET_HASH_MODE attribute.
 *
 *	To test this, we'll set the for the SRK using popup dialogs. When
 *	the context or policy object is set to include the NULL terminators,
 *	the creation of a child key for the SRK will fail with TCPA_E_AUTHFAIL,
 *	but when the context or policy object is set not to include the NULL
 *	terminators, the creation of the child key should succeed.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Create Object
 *		Create Policy
 *
 *	Test:
 *		Call Tspi_GetAttribUint32 twice then if it does not succeed
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
	char			*version;

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
	char			*function = "Tspi_GetAttribUint3205";
	TSS_HKEY		hKey;
	TSS_HCONTEXT		hContext;
	UINT32			hashMode;
	TSS_RESULT		result;
	TSS_HPOLICY		hPolicy;
	TSS_HKEY		hSRK;
	UINT32			exitCode, string_len;
	BYTE			*string;
	TSS_FLAG		initFlags = TSS_KEY_TYPE_SIGNING |
						TSS_KEY_SIZE_2048 |
						TSS_KEY_VOLATILE |
						TSS_KEY_NO_AUTHORIZATION |
						TSS_KEY_NOT_MIGRATABLE;

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
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		print_error_exit( function, err_string(result) );
		exit( result );
	}

		// Load Key by UUID for SRK
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
					    SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error( "Tspi_Context_LoadKeyByUUID", result );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		Tspi_Context_Close( hContext );
		exit( result );
	}

	string = TestSuite_Native_To_UNICODE("Click OK", &string_len);
	if (string == NULL) {
		print_error("TestSuite_Native_To_UNICODE", result);
		Tspi_Context_Close( hContext );
		exit( result );
	}

	// Set the popup string to something that instructs the tester
	result = Tspi_SetAttribData( hPolicy,
					TSS_TSPATTRIB_POLICY_POPUPSTRING,
					0,
					string_len, string );
	if (result != TSS_SUCCESS) {
		print_error("Tspi_SetAttribData", result);
		Tspi_Context_Close( hContext );
		exit( result );
	}

		//Set SRK's Secret type to popup
	result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_POPUP, 0, NULL);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		exit( result );
	}

		// Create and initialize empty object
	result = Tspi_Context_CreateObject( hContext,
						TSS_OBJECT_TYPE_RSAKEY,
						initFlags, &hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (parent key)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* This should fail due to the inclusion of NULL terminating data in
	 * the hash of the secret */
	result = Tspi_Key_CreateKey( hKey, hSRK, 0 );
	if ( result != TCPA_E_AUTHFAIL )
	{
		print_error( "Tspi_Key_CreateKey", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* flush the bad secret */
	result = Tspi_Policy_FlushSecret(hPolicy);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_FlushSecret", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	hashMode = TSS_TSPATTRIB_HASH_MODE_NOT_NULL;
	result = Tspi_SetAttribUint32( hPolicy,
					TSS_TSPATTRIB_SECRET_HASH_MODE,
					0,
					hashMode );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_SetAttribUint32", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* This should succeed now that the policy doesn't include NULL
	 * terminating data in the hash of the secret */
	result = Tspi_Key_CreateKey( hKey, hSRK, 0 );
	if ( result != TSS_SUCCESS )
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
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( exitCode );
}
