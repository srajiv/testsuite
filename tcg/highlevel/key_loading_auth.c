/*
 *
 *   Copyright (C) International Business Machines  Corp., 2005
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
 *     key_loading_auth.c
 *
 * DESCRIPTION
 *     This testcase loads NUM_KEYS keys and then attempts a bind/unbind
 *     operation using the first key loaded. The test is to make sure
 *     that even after the TSP has requested a load of more keys than the
 *     TPM can hold, an operation using one of the unloaded keys can still
 *     be performed, even when the keys require auth.
 *
 * ALGORITHM
 *	Setup:
 *	Test:
 *	Cleanup:
 *
 * USAGE
 *      First parameter is --options
 *                         -v or --version
 *      Second parameter is the version of the test case to be run
 *      This test case is currently only implemented for v1.1
 *
 * HISTORY
 *      Written by Kent Yoder <kyoder@users.sf.net>
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include <string.h>
#include <trousers/tss.h>

#include "../common/common.h"

#define NUM_KEYS	10

TSS_HKEY        hSRK;

TSS_RESULT
create_and_load_key(TSS_HCONTEXT hContext, int num, TSS_HKEY *phKey)
{
	TSS_RESULT result;
	TSS_UUID uuid;
	TSS_HPOLICY keyUsagePolicy;

	memset(&uuid, 0, sizeof(TSS_UUID));

	uuid.usTimeHigh = num;

	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						uuid, phKey );
	if ( TSS_ERROR_CODE(result) == TSS_E_PS_KEY_NOTFOUND) {
		result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
				TSS_KEY_SIZE_2048 |
				TSS_KEY_TYPE_LEGACY,
				phKey );
		if ( result != TSS_SUCCESS ) {
			print_error( "Tspi_Context_CreateObject", result );
			goto done;
		}

		result = Tspi_SetAttribUint32( *phKey, TSS_TSPATTRIB_KEY_INFO,
				TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
				TSS_ES_RSAESPKCSV15 );
		if ( result != TSS_SUCCESS )
		{
			print_error( "Tspi_SetAttribUint32", result );
			goto done;
		}

		result = Tspi_GetPolicyObject( *phKey, TSS_POLICY_USAGE, &keyUsagePolicy );
		if ( result != TSS_SUCCESS )
		{
			print_error( "Tspi_GetPolicyObject", result );
			goto done;
		}

		result = Tspi_Policy_SetSecret( keyUsagePolicy, TSS_SECRET_MODE_PLAIN,
						0, NULL );
		if ( result != TSS_SUCCESS )
		{
			print_error( "Tspi_Policy_SetSecret", result );
			goto done;
		}

		result = Tspi_Key_CreateKey( *phKey, hSRK, 0 );
		if ( result != TSS_SUCCESS ) {
			print_error( "Tspi_Key_CreateKey", result );
			goto done;
		}

		result = Tspi_Key_LoadKey( *phKey, hSRK );
		if ( result != TSS_SUCCESS ) {
			print_error( "Tspi_Key_LoadKey", result );
			goto done;
		}

		result = Tspi_Context_RegisterKey( hContext, *phKey, TSS_PS_TYPE_SYSTEM,
				uuid, TSS_PS_TYPE_SYSTEM, SRK_UUID);
		if ( result != TSS_SUCCESS ) {
			print_error( "Tspi_Context_RegisterKey", result );
		}
	}

done:
	printf("result = %x\n", result);
	return result;
}

int
main( int argc, char **argv )
{
	char		*version;

	//version = parseArgs( argc, argv );
		// if it is not version 1.1, print error
	if( strcmp(argv[2], "1.1") )
		print_wrongVersion();
	else
		return main_v1_1(argv[3]);
}

int
main_v1_1(char *argv3)
{
	char *function = "key_loading";
	int i;
	UINT32 test_result = 0;
	TSS_HKEY key_handles[NUM_KEYS];

	TSS_HCONTEXT    hContext;
	TSS_RESULT	result;
	TSS_HENCDATA	hEncData;
	TSS_HPOLICY	srkUsagePolicy, keyUsagePolicy;
	BYTE rgbDataToBind[] = {62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62};
	UINT32 ulDataLength = 16;

	UINT32 pulDataLength;
	BYTE *prgbDataToUnBind;

	print_begin_test( function );

		// Create Context
	result = Tspi_Context_Create( &hContext );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Create", result );
		print_error_exit( function, err_string(result) );
	}

		// Connect to Context
	result = Tspi_Context_Connect( hContext, NULL );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Connect", result );
		goto done;
	}

	if (argv3 && (strcmp("--clear", argv3) == 0)) {
		TSS_UUID uuid;
		memset(&uuid, 0, sizeof(uuid));
		for (i = 1; i < NUM_KEYS+1; i++) {
			uuid.usTimeHigh = i;
			if (!Tspi_Context_UnregisterKey(hContext, TSS_PS_TYPE_SYSTEM,
						   uuid, &key_handles[0]))
				printf("Unregistered key %d\n", i);
		}

		Tspi_Context_Close(hContext);
		exit(0);
	}

	fprintf(stderr, "%s connected with context 0x%x\n", function, hContext);

		//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						SRK_UUID, &hSRK );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hSRK)", result );
		goto done;
	}

		//Get Policy Object
	result = Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE,
					&srkUsagePolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		goto done;
	}

		//Set Secret
	result = Tspi_Policy_SetSecret( srkUsagePolicy, TSS_SECRET_MODE_PLAIN,
				0, NULL );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		goto done;
	}


	/* load a bunch of keys, creating when necessary */
	for (i = 1; i < NUM_KEYS+1; i++) {
		if ((result=create_and_load_key(hContext, i, &key_handles[i-1]))) {
			goto done;
		}
		printf("Loaded key %d as TSS handle %X\n", i, key_handles[i-1]);
	}

	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_ENCDATA,
						TSS_ENCDATA_BIND, &hEncData );
	if ( result != TSS_SUCCESS ) {
		print_error( "Tspi_Context_CreateObject", result );
		goto done;
	}

		// Data Bind
	result = Tspi_Data_Bind( hEncData, key_handles[0], ulDataLength, rgbDataToBind );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Data_Bind", result );
		goto done;
	}


	result = Tspi_Data_Unbind( hEncData, key_handles[0], &pulDataLength, &prgbDataToUnBind );
	if ( result != TSS_SUCCESS )
	{
		if( !(checkNonAPI(result)) )
		{
			print_error( function, result );
			goto done;
		}
		else
		{
			print_error_nonapi( function, result );
			goto done;
		}
	}
	else
	{
		if ((pulDataLength == ulDataLength) &&
			!memcmp(prgbDataToUnBind, rgbDataToBind, pulDataLength)) {
			print_success( function, result );
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit( 0 );
		} else {
			printf("%s: unbound Data doesn't match original data.\n", function);
		}
	}


done:
	print_error_exit( function, err_string(result) );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
}
