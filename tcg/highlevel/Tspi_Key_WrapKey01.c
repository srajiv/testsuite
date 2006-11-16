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
 *	Tspi_Key_WrapKey01.c
 *
 * DESCRIPTION
 *	This test will verify that once WrapKey is called
 *		and a pcr value changed, the inverse operation
 *		cannot be performed.
 *
 *	Current issues with this test:
 *		- lack of inverse operation
 *		- not sure that Invalid Handle should be returned
 *			when an incorrect pcr value is put in WrapKey
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect
 *		Get TPM
 *		Call to Load Key
 *		Create Object
 *		Load Key By UUID
 *		Get Policy Object
 *		Set Secret
 *		Get Policy Object
 *		Get Policy Object
 *		Set secret
 *		Set Secret
 *		Create Key
 *
 *	Test:	Call WrapKey01
 *		Call Get Attrib Data
 *		repeat this twice
 *	Cleanup:
 *		Print errno log and/or timing stats if options given
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1
 *
 * HISTORY
 *	Author: Megan Schneider, mschnei@us.ibm.com
 *	Altered from Kathy's original testcase (information below)
 *		on 7/27/04.
 *
 *	Author:	Kathy Robertson
 *	Date:	June 2004
 *	Email:	klrobert@us.ibm.com
 *
 * RESTRICTIONS
 *	None.
 */

#include "common.h"


int
main( int argc, char **argv )
{
	char		*version;

		//Check the Version
	version = parseArgs( argc, argv );
		//If it is not Version 1.1 then print error
	if ( strcmp(version, "1.1") )
	{
		print_wrongVersion();
	}
	else
	{
		main_v1_1();
	}
}

int
main_v1_1( void )
{
	char		*nameOfFunction = "Tspi_Key_WrapKey01";
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_FLAG	initFlags;
	TSS_HKEY	hKey;
	TSS_HKEY	hSRK;
	TSS_RESULT	result;
	TSS_UUID	uuid;
	UINT32		keySize;
	BYTE		*keyBlob;
	TSS_HPOLICY	srkUsagePolicy, keyUsagePolicy, keyMigPolicy;
	initFlags	= TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048  |
			TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
			TSS_KEY_NOT_MIGRATABLE;
	BYTE		well_known_secret[20] = TSS_WELL_KNOWN_SECRET;

	print_begin_test( nameOfFunction );

		//Create Context
	result = Tspi_Context_Create( &hContext );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Connect", result );
		print_error_exit( nameOfFunction, err_string(result) );
		exit( result );
	}
		//Connect Context
	result = Tspi_Context_Connect( hContext, NULL );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Connect", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	result = Tspi_Context_GetTpmObject( hContext, &hTPM );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Connect", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}
		//Create Object
	result = Tspi_Context_CreateObject( hContext,
					TSS_OBJECT_TYPE_RSAKEY,
					initFlags, &hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}
		//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID( hContext,
				TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID ", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_CloseObject( hContext, hKey );
		Tspi_Context_Close( hContext );
		exit( result );
	}
		//Get Policy Object
	result = Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE,
					&srkUsagePolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject ", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_CloseObject( hContext, hKey );
		Tspi_Context_Close( hContext );
		exit( result );
	}
		//Set Secret
	result = Tspi_Policy_SetSecret( srkUsagePolicy,
					TSS_SECRET_MODE_PLAIN,
					0, NULL );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret ", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_CloseObject( hContext, hKey );
		Tspi_Context_Close( hContext );
		exit( result );
	}
		//Get Policy Object
	result = Tspi_GetPolicyObject( hKey, TSS_POLICY_USAGE,
					&keyUsagePolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_CloseObject( hContext, hKey );
		Tspi_Context_Close( hContext );
		exit( result );
	}
		//Get Policy Object
	result = Tspi_GetPolicyObject( hKey, TSS_POLICY_MIGRATION,
					&keyMigPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject ", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_CloseObject( hContext, hKey );
		Tspi_Context_Close( hContext );
		exit( result );
	}
		//Set secret
	result = Tspi_Policy_SetSecret( keyMigPolicy,
				TSS_SECRET_MODE_SHA1,
				20, well_known_secret );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret ", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_CloseObject( hContext, hKey );
		Tspi_Context_Close( hContext );
		exit( result );
	}
		//Set Secret
	result = Tspi_Policy_SetSecret( keyUsagePolicy,
				TSS_SECRET_MODE_SHA1,
				20, well_known_secret );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret ", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_CloseObject( hContext, hKey );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		//Create Key/*5*/
	result = Tspi_Key_CreateKey( hKey, hSRK, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_CloseObject( hContext, hKey );
		Tspi_Context_Close( hContext );
		exit( result );
	}
		//Wrap Key
	result = Tspi_Key_WrapKey( hKey, hSRK, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_WrapKey", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_CloseObject( hContext, hKey );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_GetAttribData( hKey, TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_BLOB,
					&keySize, &keyBlob );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetAttribData", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_CloseObject( hContext, hKey );
		Tspi_Context_Close( hContext );
		exit( result );
	}

/*	result = Tspi_PcrComposite_SetPcrValue( hKey, TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_BLOB,
					&keySize, &keyBlob );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetAttribData", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_CloseObject( hContext, hKey );
		Tspi_Context_Close( hContext );
		exit( result );
	} */
		//Wrap Key
	result = Tspi_Key_WrapKey( hKey, hSRK, 1 );
	if ( TSS_ERROR_CODE(result) != TSS_E_INVALID_HANDLE )
	{
		print_error( "Tspi_Key_WrapKey (2nd)", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_CloseObject( hContext, hKey );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_GetAttribData( hKey, TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_BLOB,
					&keySize, &keyBlob );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetAttribData", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_CloseObject( hContext, hKey );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	print_success( nameOfFunction, result );
	print_end_test( nameOfFunction );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_CloseObject( hContext, hKey );
	Tspi_Context_Close( hContext );
	exit( 0 );
}
