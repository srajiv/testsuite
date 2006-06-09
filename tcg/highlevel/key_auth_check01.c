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
 *	key_auth_check01.c
 *
 * DESCRIPTION
 *	This test will verify that a key can be created with auth and used to
 *	 sign some data. If this test returns success, key_auth_check02 should
 *	 be run after a complete platform reset. This will make sure that the
 *	 same key is read from system PS and auth is still required when the key
 *	 is used again.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Load SRK
 *		Get Policy Object
 *		Set Secret
 *		Create Signing Key Object
 *		Get Policy Object
 *		Set Secret
 *		Create Signing Key
 *		Load Key
 *		Create Hash Object
 *		Update Hash Value
 *		Sign Hash object data
 *		If all succeeds, register the signing key
 *
 *	Cleanup:
 *		Unregister system key
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
 *	Kent Yoder, shpedoikal@gmail.com 10/12/2004
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include <trousers/tss.h>
#include "../common/common.h"


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
	char		*function = "key_auth_check01";
	TSS_HCONTEXT	hContext;
	UINT32		exitCode;
	TSS_HKEY	hSRK;
	TSS_HKEY	hMSigningKey;
	TSS_UUID	migratableSignUUID = {0x1, 0x55, 0x67, 0x8, 0x5, { 6, 7, 8, 9, 10, 2 } };
	TSS_HHASH	hHash;
	BYTE		*prgbSignature;
	UINT32		pulSignatureLength;
	TSS_RESULT	result;
	TSS_HPOLICY	srkUsagePolicy, keyUsagePolicy;

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

		//Load Key By UUID
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

		//Get Policy Object
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

		//Set Secret
	result = Tspi_Policy_SetSecret( srkUsagePolicy, TESTSUITE_SRK_SECRET_MODE,
				TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		//Create Signing Key
	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
						TSS_KEY_SIZE_2048 |
						TSS_KEY_TYPE_SIGNING |
						TSS_KEY_AUTHORIZATION,
						&hMSigningKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (signing key)",
				result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// get signing key's policy
	result = Tspi_GetPolicyObject( hMSigningKey, TSS_POLICY_USAGE,
					&keyUsagePolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		//Set Secret
	result = Tspi_Policy_SetSecret( keyUsagePolicy, TESTSUITE_KEY_SECRET_MODE,
					TESTSUITE_KEY_SECRET_LEN, TESTSUITE_KEY_SECRET );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Key_CreateKey( hMSigningKey, hSRK, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (signing key)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Key_LoadKey( hMSigningKey, hSRK );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKey (hMSigningKey)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// create hash
	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_HASH,
						TSS_HASH_SHA1, &hHash );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (hash)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Hash_UpdateHashValue( hHash, 20, "Je pense, danc je s" );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Hash_SetHashValue", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}


	result = Tspi_Hash_Sign( hHash, hMSigningKey, &pulSignatureLength,
					&prgbSignature );
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
		result = Tspi_Context_RegisterKey(hContext, hMSigningKey, TSS_PS_TYPE_SYSTEM,
						migratableSignUUID, TSS_PS_TYPE_SYSTEM, SRK_UUID);
		if (result != TSS_SUCCESS)
		{
			print_error( "Tspi_Context_RegisterKey", result );
			print_error_exit( function, err_string(result) );
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit( result );
		}
		print_success( function, result );
		exitCode = 0;
	}

	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( exitCode );
}
