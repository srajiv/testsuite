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
 *	Tspi_TPM_GetAuditDigest02.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_TPM_GetAuditDigest
 *		returns TSS_SUCCESS using a key with authorization 
 *      and the authorization data.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Get TPM Handle
 *
 *	Test:
 *		Call TPM_GetAuditDigest without a key handle.
 *		Make sure that it returns the proper return codes
 *		Print results
 *		Call TPM_GetAuditDigest with a key handle.
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
 *      This test case is currently only implemented for v1.2
 *
 * HISTORY
 *      Tom Lendacky, toml@us.ibm.com, 6/07.
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include "common.h"


int
main( int argc, char **argv )
{
	char		version;

	version = parseArgs( argc, argv );
	if (version >= TESTSUITE_TEST_TSS_1_2)
		main_v1_2(version);
	else
		print_NA();
}

int
main_v1_2( char version )
{
	char *			function = "Tspi_TPM_GetAuditDigest02";
	TSS_HCONTEXT		hContext;
	TSS_HKEY		hSRK;
	TSS_HTPM		hTPM;
	TSS_HPOLICY		hTpmPolicy;
	TSS_HKEY		hKey;
	UINT32			auditDigestLen, ordListLen;
	BYTE *			auditDigest;
	UINT32 *		ordList;
	TPM_COUNTER_VALUE	counterValue;
	TSS_RESULT		result;
	TSS_VALIDATION  valData;
	BYTE*			data;

	print_begin_test( function );

	result = connect_load_all(&hContext, &hSRK, &hTPM);
	if ( result != TSS_SUCCESS )
	{
		print_error( "connect_load_all", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTpmPolicy);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Policy_SetSecret(hTpmPolicy, TESTSUITE_OWNER_SECRET_MODE,
					TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* Check if ordinal auditing is supported on this TPM */
	result = Testsuite_Is_Ordinal_Supported(hTPM, TPM_ORD_SetOrdinalAuditStatus);
	if (result != TSS_SUCCESS) {
		fprintf(stderr, "%s: TPM doesn't support auditing, returning success\n", __FILE__);
		print_success( function, TSS_SUCCESS );
		print_end_test( function );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( 0 );
	}

		//Call GetAuditDigest
	result = Tspi_TPM_GetAuditDigest(hTPM, NULL_HKEY, FALSE, &auditDigestLen, &auditDigest,
					 &counterValue, NULL, &ordListLen, &ordList);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_TPM_GetAuditDigest", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	} else {
		result = Tspi_Context_FreeMemory(hContext, auditDigest);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Context_FreeMemory ", result);
			Tspi_Context_Close(hContext);
			exit(result);
		}

		result = Tspi_Context_FreeMemory(hContext, (BYTE *)ordList);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Context_FreeMemory ", result);
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}

	result = create_load_key(hContext, TSS_KEY_TYPE_SIGNING | TSS_KEY_AUTHORIZATION, hSRK, &hKey);
	if ( result != TSS_SUCCESS )
	{
		print_error( "create_load_key", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* Set the Validation Data */
	result = Tspi_TPM_GetRandom( hTPM, 20, &data );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_TPM_GetRandom", result );
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close(hContext);
		exit(result);
	}

	valData.ulExternalDataLength = 20;
	valData.rgbExternalData = data;


		//Call GetAuditDigest
	result = Tspi_TPM_GetAuditDigest(hTPM, hKey, FALSE, &auditDigestLen, &auditDigest,
					 &counterValue, &valData, NULL, NULL);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_TPM_GetAuditDigest", result );
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	} else {
		result = Tspi_Context_FreeMemory(hContext, auditDigest);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Context_FreeMemory ", result);
			Tspi_Context_Close(hContext);
			exit(result);
		}

		/* Check the signature */
		result = Testsuite_Verify_Signature(hContext, hKey, &valData);
		if (result != TSS_SUCCESS){
			print_error("Error on signature checking", result);
		}else{
			fprintf(stderr, "TPM Signature Verification Successful\n");
			print_success( function, result );
		}
	}

	print_end_test( function );
	Tspi_Context_CloseObject(hContext, hKey);
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( 0 );
}
