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
 *	Tspi_Data_Unseal04.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_Data_Unseal works regardless of
 *	whether the key or encdata objects have passwords associated with
 *	them.
 *
 * ALGORITHM
 *	Setup:
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
 *      Kent Yoder, kyoder@users.sf.net, 11/16/05
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
	char		*function = "Tspi_Data_Unseal04";
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_HKEY	hSRK, hAuthKey, hNoAuthKey;
	TSS_HPOLICY	hAuthKeyPolicy, hAuthEncDataPolicy;
	BYTE		*rgbPcrValue;
	UINT32		ulPcrLen;
	TSS_HENCDATA	hNoAuthEncData, hAuthEncData;
	BYTE		*prgbDataToUnseal;
	TSS_HPCRS	hPcrs, hNullPcrs = 0;
	UINT32		BlobLength;
	TSS_RESULT	result;
	TSS_FLAG	initFlags = TSS_KEY_TYPE_STORAGE | TSS_KEY_SIZE_2048  |
				    TSS_KEY_VOLATILE | TSS_KEY_NOT_MIGRATABLE;

	print_begin_test( function );

	result = connect_load_all(&hContext, &hSRK, &hTPM);
	if ( result != TSS_SUCCESS )
	{
		print_error( "connect_load_srk", result );
		print_error_exit( function, err_string(result) );
		exit( result );
	}

	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   initFlags | TSS_KEY_NO_AUTHORIZATION,
					   &hNoAuthKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   initFlags | TSS_KEY_AUTHORIZATION,
					   &hAuthKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_ENCDATA,
					   TSS_ENCDATA_SEAL, &hNoAuthEncData );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_ENCDATA,
					   TSS_ENCDATA_SEAL, &hAuthEncData );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = set_secret(hAuthKey, NULL);
	if ( result != TSS_SUCCESS )
	{
		print_error( "set_secret", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = set_secret(hAuthEncData, NULL);
	if ( result != TSS_SUCCESS )
	{
		print_error( "set_secret", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// Create the auth key
	result = Tspi_Key_CreateKey( hAuthKey, hSRK, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Key_LoadKey( hAuthKey, hSRK );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_LoadKey", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// Create the noauth key
	result = Tspi_Key_CreateKey( hNoAuthKey, hSRK, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Key_LoadKey( hNoAuthKey, hSRK );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_LoadKey", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS,
					   0, &hPcrs );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

#define PCR_NUM	5

	result = Tspi_TPM_PcrRead( hTPM, PCR_NUM, &ulPcrLen, &rgbPcrValue );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_TPM_PcrRead", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_PcrComposite_SetPcrValue( hPcrs, PCR_NUM, ulPcrLen,
							rgbPcrValue );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_PcrComposite_SetPcrValue", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* Now the setup is done, run through several different tests:
	 *
	 *   Test#	Key Auth?	EncData Auth?	Pcr Value Set?
	 *
	 *     1
	 *     2					X
	 *     3			X
	 *     4			X		X
	 *     5	X
	 *     6	X				X
	 *     7	X		X
	 *     8	X		X		X
	 */

	/* test 1 */
	result = seal_and_unseal(hContext, hNoAuthKey, hNoAuthEncData, hNullPcrs);
	if ( result != TSS_SUCCESS )
	{
		print_error("Test 1", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* test 2 */
	result = seal_and_unseal(hContext, hNoAuthKey, hNoAuthEncData, hPcrs);
	if ( result != TSS_SUCCESS )
	{
		print_error("Test 2", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* test 3 */
	result = seal_and_unseal(hContext, hNoAuthKey, hAuthEncData, hNullPcrs);
	if ( result != TSS_SUCCESS )
	{
		print_error("Test 3", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* test 4 */
	result = seal_and_unseal(hContext, hNoAuthKey, hAuthEncData, hPcrs);
	if ( result != TSS_SUCCESS )
	{
		print_error("Test 4", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* test 5 */
	result = seal_and_unseal(hContext, hAuthKey, hNoAuthEncData, hNullPcrs);
	if ( result != TSS_SUCCESS )
	{
		print_error("Test 5", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* test 6 */
	result = seal_and_unseal(hContext, hAuthKey, hNoAuthEncData, hPcrs);
	if ( result != TSS_SUCCESS )
	{
		print_error("Test 6", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* test 7 */
	result = seal_and_unseal(hContext, hAuthKey, hAuthEncData, hNullPcrs);
	if ( result != TSS_SUCCESS )
	{
		print_error("Test 7", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* test 8 */
	result = seal_and_unseal(hContext, hAuthKey, hAuthEncData, hPcrs);
	if ( result != TSS_SUCCESS )
	{
		print_error("Test 8", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	print_success( function, result );
	print_end_test( function );
	Tspi_Context_Close( hContext );
	exit( result );
}
