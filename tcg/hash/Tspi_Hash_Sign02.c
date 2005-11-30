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
 *	Tspi_Hash_Sign02.c
 *
 * DESCRIPTION
 *	This test will return TSS_E_INVALID_HANDLE, because
 *		hMSigningKey is not loaded before being
 *		passed as the second parameter in Hash_Sign,
 *		and whHash = -1 is passed as the first parameter.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Load SRK
 *		Get Policy Object
 *		Set Secret
 *		Create Signing Key Object
 *		Create Signing Key
 *		Register Key
 *		Create Hash Object
 *		Set Hash Value
 *
 *	Test:
 *		Call Hash_Sign then if it does not succeed
 *		Make sure that it returns the proper return codes
 *		Print results
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
 *      Megan Schneider, mschnei@us.ibm.com, 6/04.
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
	char		*function = "Tspi_Hash_Sign02";
	TSS_HCONTEXT	hContext;
	TSS_HKEY	hSRK;
	TSS_HKEY	hMSigningKey;
	TSS_UUID	SRKUUID			= {0,0,0,0,0,0,0,0,0,0,1};
	TSS_UUID	migratableSignUUID	= {1,2,3,4,5,6,7,8,9,10,2};
	TSS_HHASH	hHash;
	TSS_HHASH	whHash = -1;
	BYTE		*prgbSignature;
	UINT32		pulSignatureLength, exitCode = 0;
	TSS_RESULT	result;
	TSS_HPOLICY	srkUsagePolicy;

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
	result = Tspi_Policy_SetSecret( srkUsagePolicy, TSS_SECRET_MODE_PLAIN,
				0, NULL );
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
						TSS_KEY_MIGRATABLE,
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

	result = Tspi_Key_CreateKey( hMSigningKey, hSRK, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (signing key)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_RegisterKey( hContext, hMSigningKey,
						TSS_PS_TYPE_SYSTEM,
						migratableSignUUID,
						TSS_PS_TYPE_SYSTEM,
						SRKUUID );
	if ( (result != TSS_SUCCESS) &&
		(TSS_ERROR_CODE(result) != TSS_E_KEY_ALREADY_REGISTERED) )
	{
		print_error( "Tspi_Context_RegisterKey (signing key)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

/*	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						migratableSignUUID,
						&hMSigningKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (signing key)",
				result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM,
						migratableSignUUID,
						&hMSigningKey );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
*/
	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_HASH,
						TSS_HASH_SHA1, &hHash );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (hash)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM,
						migratableSignUUID,
						&hMSigningKey );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Hash_SetHashValue( hHash, 20, "Je pense, danc je suis." );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Hash_SetHashValue", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM,
						migratableSignUUID,
						&hMSigningKey );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Hash_Sign( whHash, hMSigningKey, &pulSignatureLength,
					&prgbSignature );
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
	}

	print_end_test( function );
	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_SYSTEM,
					migratableSignUUID,
					&hMSigningKey );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( exitCode );
}
