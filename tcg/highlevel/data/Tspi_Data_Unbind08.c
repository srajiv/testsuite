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
 *	Tspi_Data_Unbind08.c
 *
 * DESCRIPTION
 *	This test will verify that the bind/unbind functions return valid error
 *	codes when the data to bind is too big or too small.
 *
 * ALGORITHM
 *	Setup:
 *
 *	Test:
 *		Call Data_Unbind then if it does not succeed
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
 *      Kent Yoder, kyoder@users.sf.net, 08/31/06
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include "common.h"


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

/* This is the max data size for a LEGACY key with PKCS1.5 padding*/
#define DATA_SIZE	4097

int
main_v1_1( void )
{
	char		*function = "Tspi_Data_Unbind08";
	TSS_HCONTEXT	hContext;
	TSS_HKEY	hSRK;
	TSS_HKEY	hLegacyKey, hBindPKCSKey, hBindOAEPKey;
	TSS_HPOLICY	hSrkPolicy;
	BYTE		*prgbDataToUnBind;
	TSS_HENCDATA	hEncData;
	UINT32		pulDataLength;
	BYTE		rgbDataToBind[DATA_SIZE], *rgbEncryptedData = NULL;
	UINT32		ulDataLength = DATA_SIZE, ulEncryptedDataLength = 0;
	TSS_UUID	uuid;
	TSS_RESULT	result;

	print_begin_test( function );

	memset (rgbDataToBind, 0x5a, DATA_SIZE);

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

		// create hLegacyKey
	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_512,
					   &hLegacyKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (hKey)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	result = Tspi_SetAttribUint32(hLegacyKey, TSS_TSPATTRIB_KEY_INFO,
				      TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
				      TSS_ES_RSAESPKCSV15);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_SetAttribUint32", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   TSS_KEY_TYPE_BIND|TSS_KEY_SIZE_512,
					   &hBindPKCSKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (hKey)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	result = Tspi_SetAttribUint32(hBindPKCSKey, TSS_TSPATTRIB_KEY_INFO,
				      TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
				      TSS_ES_RSAESPKCSV15);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_SetAttribUint32", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   TSS_KEY_TYPE_BIND|TSS_KEY_SIZE_512,
					   &hBindOAEPKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (hKey)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}



	result = Tspi_Context_CreateObject( hContext,
						TSS_OBJECT_TYPE_ENCDATA,
						TSS_ENCDATA_BIND, &hEncData );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (hEncData)", result );
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

#ifndef TESTSUITE_NOAUTH_SRK
	result = Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE, &hSrkPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Policy_SetSecret( hSrkPolicy, TESTSUITE_SRK_SECRET_MODE,
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

	result = Tspi_Key_CreateKey( hLegacyKey, hSRK, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	result = Tspi_Key_CreateKey( hBindPKCSKey, hSRK, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	result = Tspi_Key_CreateKey( hBindOAEPKey, hSRK, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* Test 1: No data in the hEncData object, try to unbind
	 * Expected result: TSS_E_ENC_NO_DATA
	 */
	result = Tspi_Data_Unbind(hEncData, hLegacyKey, &pulDataLength, &prgbDataToUnBind);
	if (TSS_ERROR_CODE(result) != TSS_E_ENC_NO_DATA)
	{
		print_verifyerr("result == TSS_E_ENC_NO_DATA", TSS_E_ENC_NO_DATA,
				TSS_ERROR_CODE(result));
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success("Test 1", result);

	/* Test 2: Try to bind data that's too big for the RSA modulus (512 bits)
	 * Using: TSS_KEY_TYPE_LEGACY, PKCSv1.5 padding
	 * Expected result: TSS_E_ENC_INVALID_LENGTH
	 */
	result = Tspi_Data_Bind(hEncData, hLegacyKey, ulDataLength, rgbDataToBind);
	if (TSS_ERROR_CODE(result) != TSS_E_ENC_INVALID_LENGTH )
	{
		print_error("Tspi_Data_Bind", result);
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success("Test 2", result);

	/* Test 3: Try to bind data that's too big for the RSA modulus (512 bits)
	 * Using: TSS_KEY_TYPE_BIND, PKCSv1.5 padding
	 * Expected result: TSS_E_ENC_INVALID_LENGTH
	 */
	result = Tspi_Data_Bind(hEncData, hBindPKCSKey, ulDataLength, rgbDataToBind);
	if (TSS_ERROR_CODE(result) != TSS_E_ENC_INVALID_LENGTH )
	{
		print_error("Tspi_Data_Bind", result);
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success("Test 3", result);

	/* Test 4: Try to bind data that's too big for the RSA modulus (512 bits)
	 * Using: TSS_KEY_TYPE_BIND OAEP padding
	 * Expected result: TSS_E_ENC_INVALID_LENGTH
	 */
	result = Tspi_Data_Bind(hEncData, hBindOAEPKey, ulDataLength, rgbDataToBind);
	if (TSS_ERROR_CODE(result) != TSS_E_ENC_INVALID_LENGTH )
	{
		print_error("Tspi_Data_Bind", result);
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success("Test 4", result);

	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( 0 );
}
