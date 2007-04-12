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
 *	Tspi_Context_RegisterKey01.c
 *
 * DESCRIPTION
 *      This test will create 5 keys, then register and unregister them in
 *      different orders in order to stress the persistent store.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Load SRK by UUID
 *		Get Policy Object
 *		Set Secret
 *		Create Object (signing key)
 *		Create Key (signing key)
 *			(first call - system)
 *
 *	Test:
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
 *      Kent Yoder <kyoder@users.sf.net>
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
	char version;

	version = parseArgs( argc, argv );
	if (version)
		main_v1_1();
	else
		print_wrongVersion();
}

#define NUM_KEYS	5

struct key {
	TSS_HKEY handle;
	TSS_UUID uuid;
	int registered;
} hKey[NUM_KEYS];

TSS_HCONTEXT	hContext;
TSS_HKEY	throw_away;

TSS_RESULT
registerkey(int i)
{
	TSS_RESULT result;
	char *function = "Tspi_Context_RegisterKey";

	printf("%s: key %d\n", __FUNCTION__, i);
	result = Tspi_Context_RegisterKey( hContext, hKey[i].handle,
						TSS_PS_TYPE_SYSTEM,
						hKey[i].uuid,
						TSS_PS_TYPE_SYSTEM,
						SRK_UUID );
	if (result != TSS_SUCCESS)
	{
		if( !(checkNonAPI(result)) )
		{
			print_error( function, result );
			return result;
		}
		else
		{
			print_error_nonapi( function, result );
			return result;
		}
	}
	else
	{
		hKey[i].registered = 1;
		print_success( function, result );
		return 0;
	}
}

TSS_RESULT
unregisterkey(int i)
{
	TSS_RESULT result;
	char *function = "Tspi_Context_UnregisterKey";

	printf("%s: key %d\n", __FUNCTION__, i);
	result = Tspi_Context_UnregisterKey( hContext,
						TSS_PS_TYPE_SYSTEM,
						hKey[i].uuid,
						&throw_away );
	if (result != TSS_SUCCESS)
	{
		if( !(checkNonAPI(result)) )
		{
			print_error( function, result );
			return result;
		}
		else
		{
			print_error_nonapi( function, result );
			return result;
		}
	}
	else
	{
		hKey[i].registered = 0;
		print_success( function, result );
		return 0;
	}
}

int
main_v1_1( void )
{
	char		*function = "Tspi_Context_RegisterKey05";
	TSS_HKEY	hSRK;
	TSS_HTPM	hTPM;
	TSS_RESULT	result;
	TSS_HPOLICY	srkUsagePolicy;
	int		i;
	BYTE		*rand;

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

	/* initialize the struct */
	for (i = 0; i < NUM_KEYS; i++)
	{
		result = Tspi_TPM_GetRandom( hTPM, sizeof(TSS_UUID), &rand);
		if ( result != TSS_SUCCESS )
		{
			print_error( "Tspi_TPM_GetRandom", result );
			print_error_exit( function, err_string(result) );
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit( result );
		}

		memcpy(&hKey[i].uuid, rand, sizeof(TSS_UUID));
		Tspi_Context_FreeMemory(hContext, rand);
		hKey[i].registered = hKey[i].handle = 0;
	}

		// Load SRK
	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						SRK_UUID, &hSRK );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hSRK)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

#ifndef TESTSUITE_NOAUTH_SRK
		// Get SRK Usage Policy
	result = Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE,
					&srkUsagePolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// set secret
	result = Tspi_Policy_SetSecret( srkUsagePolicy, TESTSUITE_SRK_SECRET_MODE,
					TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret (1)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
#endif

	/* create NUM_KEYS keys */
	for (i = 0; i < NUM_KEYS; i++)
	{
		// create object
		result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
				TSS_KEY_SIZE_2048 | TSS_KEY_TYPE_SIGNING,
				&hKey[i].handle );
		if ( result != TSS_SUCCESS )
		{
			print_error( "Tspi_Context_CreateObject", result );
			print_error_exit( function, err_string(result) );
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit( result );
		}

		// create signing key
		result = Tspi_Key_CreateKey( hKey[i].handle, hSRK, 0 );
		if ( (result != TSS_SUCCESS) )
		{
			print_error( "Tspi_Key_CreateKey", result );
			print_error_exit( function, err_string(result) );
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit( result );
		}
	}

	/* all in order */
	for (i = 0; i < NUM_KEYS; i++)
	{
		if ((result = registerkey(i))) {
			printf("%d: registerkey error, key %d\n", __LINE__, i);
			goto cleanup;
		}
	}
	for (i = 0; i < NUM_KEYS; i++)
	{
		if ((result = unregisterkey(i))) {
			printf("%d: unregisterkey error, key %d\n", __LINE__, i);
			goto cleanup;
		}
	}

	/* backwards */
	for (i = 0; i < NUM_KEYS; i++)
	{
		if ((result = registerkey(i))) {
			printf("%d: registerkey error, key %d\n", __LINE__, i);
			goto cleanup;
		}
	}
	for (i = NUM_KEYS-1; i >= 0; i--)
	{
		if ((result = unregisterkey(i))) {
			printf("%d: unregisterkey error, key %d\n", __LINE__, i);
			goto cleanup;
		}
	}

	print_end_test( function );
cleanup:
	for (i = 0; i < NUM_KEYS; i++) {
		if (hKey[i].registered == 1) {
			Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM,
							hKey[i].uuid, &throw_away);
		}
	}

	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( result );
}
