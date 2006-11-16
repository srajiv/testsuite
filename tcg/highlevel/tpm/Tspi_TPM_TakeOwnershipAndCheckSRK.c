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
 *	Tspi_TPM_TakeOwnershipAndCheckSRK.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_TPM_TakeOwnership succeeds when a
 *	handle to the public endorsement key is passed in to it explicitly.
 *	Also, the SRK public key should only be returned after a call to
 *	Tspi_Key_GetPubKey, unless the handle to the SRK is the handle
 *	created by taking ownership. This test will check that, also.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Get TPM Object
 *		Get Policy Object
 *		Set Secret
 *		Get Public Endorsement Key
 *		Create SRK
 *		Get Policy Object
 *		Set Secret
 *
 *	Test:
 *		Call TPM_TakeOwnership then if it does not succeed
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
	char			*function = "Tspi_TPM_TakeOwnershipAndCheckSRK";
	BYTE			*rgbPcrValue;
	UINT32			ulPcrValueLength;
	TSS_HCONTEXT		hContext;
	TSS_HTPM		hTPM;
	TSS_HPOLICY		hPolicy;
	TSS_HPOLICY		hSrkPolicy;
	TSS_HKEY		hEndorsement;
	TSS_HKEY		hKeySRK;
	BYTE			*pubBlob, zeroBlob[2048];
	TSS_VALIDATION		valid;
	TSS_RESULT		result;
	UINT32			exitCode, pubBlobLen;

	print_begin_test( function );

	memset(zeroBlob, 0, sizeof(zeroBlob));

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

	result = Tspi_GetPolicyObject( hTPM, TSS_POLICY_USAGE, &hPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Policy_SetSecret( hPolicy, TESTSUITE_OWNER_SECRET_MODE,
					TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_TPM_GetPubEndorsementKey( hTPM, 0, NULL, &hEndorsement );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_TPM_GetPubEndorsementKey", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
						TSS_KEY_TSP_SRK, &hKeySRK );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

#ifndef TESTSUITE_NOAUTH_SRK
	result = Tspi_GetPolicyObject( hKeySRK, TSS_POLICY_USAGE,
					&hSrkPolicy );
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

	result = Tspi_TPM_TakeOwnership( hTPM, hKeySRK, hEndorsement );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_TPM_TakeOwnership", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* the true SRK public key should be visible to us now,
	 * since we just took ownership */
	result = Tspi_GetAttribData(hKeySRK, TSS_TSPATTRIB_RSAKEY_INFO,
				    TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
				    &pubBlobLen, &pubBlob);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetAttribData (SRK public key)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* Do a memcmp with all 0's, since there's not another good way to
	 * verify that this is a valid public key */
	if (!memcmp(pubBlob, zeroBlob, pubBlobLen))
	{
		printf("memcmp failed, the SRK public key is not available\n");
		print_error( "memcmp", 0 );
		print_error_exit( function, "No SRK public key" );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	Tspi_Context_FreeMemory(hContext, pubBlob);

	/* Now close the SRK's key handle */
	result = Tspi_Context_CloseObject(hContext, hKeySRK);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CloseObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	hKeySRK = NULL_HKEY;

	/* Now reload the SRK by UUID from PS. */
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
					    SRK_UUID, &hKeySRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

#ifndef TESTSUITE_NOAUTH_SRK
	/* set the SRK secret, needed for the retrieval of the pub key
	 * below. */
	result = Tspi_GetPolicyObject( hKeySRK, TSS_POLICY_USAGE,
					&hSrkPolicy );
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

	/* Trying to get the true SRK public key should return
	 * TSS_E_BAD_PARAMETER to us now. */
	result = Tspi_GetAttribData(hKeySRK, TSS_TSPATTRIB_RSAKEY_INFO,
				    TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
				    &pubBlobLen, &pubBlob);
	if ( result != TSS_E_BAD_PARAMETER )
	{
		print_error( "Tspi_GetAttribData (SRK public key)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}
#if 0
	/* XXX TODO */
	result = Tspi_GetAttribData(hKeySRK, TSS_TSPATTRIB_RSAKEY_INFO,
				    TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
				    &pubBlobLen, &pubBlob);
	if ( result != TSS_E_BAD_PARAMETER )
	{
		print_error( "Tspi_GetAttribData (SRK public key)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}
#endif
	result = Tspi_Key_GetPubKey(hKeySRK, &pubBlobLen, &pubBlob);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_GetPubKey", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}


	/* verify that this is a valid public key */
	if (!memcmp(pubBlob, zeroBlob, pubBlobLen))
	{
		printf("memcmp failed, the SRK public key is all 0's\n");
		print_error( "memcmp", 0 );
		print_error_exit( function, "No SRK public key was returned "
				 "from Tspi_Key_GetPubKey" );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	Tspi_Context_FreeMemory(hContext, pubBlob);

	print_success( function, result );
	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( exitCode );
}
