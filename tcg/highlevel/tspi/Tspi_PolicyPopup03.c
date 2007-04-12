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
 *	Tspi_PolicyPopup03.c
 *
 * DESCRIPTION
 *	This test will verify that a policy set to display
 *		a popup correctly displays the set popup
 *		and also returns an error message when unable
 *		to do so.
 *
 *	Current issues with this test:
 *		- CreateKey dies with AuthFail
 *		- two password prompts come up, if the first one
 *			is removed, dies with internal error
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Create Object
 *		Get Policy
 *		Set Policy to display popup
 *
 *	Test:
 *		Use Policy
 *		Set context to silent
 *		Verify that attempting to use the policy results
 *			in an error message
 *		Set context to not silent
 *		Use Policy
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
	char			*function = "Tspi_PolicyPopup03";
	char			*hashData = "09876543210987654321";
	TSS_RESULT		result;
	TSS_HKEY		hSRK, hKey;
	TSS_UUID		SRKUUID	= {0,0,0,0,0,0,0,0,0,0,1};
	TSS_HPOLICY		hPolicy;
	TSS_HCONTEXT		hContext;
	TSS_HHASH		hHash;
	BYTE			*popupMsg = NULL;
	BYTE			*msg = "Enter a password for a new key:";
	UINT32			msg_len;
	TSS_HPOLICY		srkUsagePolicy;
	TSS_FLAG		initFlags = TSS_KEY_TYPE_SIGNING |
						TSS_KEY_SIZE_2048 |
						TSS_KEY_VOLATILE |
						TSS_KEY_AUTHORIZATION |
						TSS_KEY_NOT_MIGRATABLE;
	UINT32			ulSignatureLen;
	BYTE			*signature;

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
#endif

	result = Tspi_Context_CreateObject ( hContext,
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

	result = Tspi_GetPolicyObject ( hKey, TSS_POLICY_USAGE, &hPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	popupMsg = char_to_unicode(msg, &msg_len);
	result = Tspi_SetAttribData( hPolicy,
					TSS_TSPATTRIB_POLICY_POPUPSTRING,
					0, msg_len, popupMsg );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_SetAttribData", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	free(popupMsg);

	result = Tspi_Policy_SetSecret( hPolicy,
					TSS_SECRET_MODE_POPUP,
					0, NULL );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Key_CreateKey( hKey, hSRK, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (hKey)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Key_LoadKey( hKey, hSRK );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_LaodKey", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Policy_FlushSecret( hPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	popupMsg = char_to_unicode("Re-enter the new key's password:", &msg_len);
	result = Tspi_SetAttribData( hPolicy,
					TSS_TSPATTRIB_POLICY_POPUPSTRING,
					0, msg_len, popupMsg );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_SetAttribData", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	free(popupMsg);
#if 0
	result = Tspi_Policy_SetSecret( hPolicy,
					TSS_SECRET_MODE_POPUP,
					0, NULL );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
#endif
	/* now sign some data to test the key's auth data */
	result = Tspi_Context_CreateObject ( hContext,
						TSS_OBJECT_TYPE_HASH,
						TSS_HASH_SHA1, &hHash );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (hKey)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}


	result = Tspi_Hash_SetHashValue ( hHash, strlen(hashData), hashData );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Hash_SetHashValue", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Hash_Sign ( hHash, hKey, &ulSignatureLen, &signature );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Hash_Sign", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	print_success( function, result );
	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( 0 );
}
