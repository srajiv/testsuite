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
 *	Tspi_TPM_Delegate_VerifyDelegation01.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_TPM_Delegate_UpdateVerificationCount
 *		returns TSS_SUCCESS.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Get TPM Handle
 *		Create a delegation family
 *		Create an owner delegation blob
 *		Create another owner delegation blob
 *			this time incrementing the verification count
 *
 *	Test:
 *		Call TPM_Delegate_VerifyDelegation on the first owner delegation blob.
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
 *      Tom Lendacky, toml@us.ibm.com, 7/07.
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
	char *			function = "Tspi_TPM_Delegate_VerifyDelegation-trans01";
	TSS_HCONTEXT		hContext;
	TSS_HKEY		hSRK, hSigningKey, hWrappingKey;
	TSS_HTPM		hTPM;
	TSS_HPOLICY		hTPMPolicy;
	TSS_HPOLICY		hDelegation1 = NULL_HPOLICY;
	TSS_HPOLICY		hDelegation2 = NULL_HPOLICY;
	TSS_HDELFAMILY		hFamily = NULL_HDELFAMILY;
	TSS_RESULT		result;

	print_begin_test( function );

	result = connect_load_all(&hContext, &hSRK, &hTPM);
	if ( result != TSS_SUCCESS )
	{
		print_error( "connect_load_all", (result) );
		goto done;
	}

	result = Testsuite_Transport_Init(hContext, hSRK, hTPM, TRUE, FALSE, &hWrappingKey,
					  &hSigningKey);
	if (result != TSS_SUCCESS) {
		print_error("Testsuite_Transport_Init", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_GetPolicyObject( hTPM, TSS_POLICY_USAGE, &hTPMPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		goto done;
	}

	result = Tspi_Policy_SetSecret( hTPMPolicy, TESTSUITE_OWNER_SECRET_MODE,
					TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		goto done;
	}

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hDelegation1);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject", (result) );
		goto done;
	}

	result = Tspi_Policy_SetSecret( hDelegation1, TESTSUITE_DELEGATE_SECRET_MODE,
					TESTSUITE_DELEGATE_SECRET_LEN, TESTSUITE_DELEGATE_SECRET );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		goto done;
	}

	result = Tspi_SetAttribUint32(hDelegation1, TSS_TSPATTRIB_POLICY_DELEGATION_INFO,
			TSS_TSPATTRIB_POLDEL_TYPE, TSS_DELEGATIONTYPE_OWNER);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_SetAttribUint32", (result) );
		goto done;
	}

	result = Tspi_SetAttribUint32(hDelegation1, TSS_TSPATTRIB_POLICY_DELEGATION_INFO,
			TSS_TSPATTRIB_POLDEL_PER1, 0);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_SetAttribUint32", (result) );
		goto done;
	}

	result = Tspi_SetAttribUint32(hDelegation1, TSS_TSPATTRIB_POLICY_DELEGATION_INFO,
			TSS_TSPATTRIB_POLDEL_PER2, 0);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_SetAttribUint32", (result) );
		goto done;
	}

	result = Tspi_TPM_Delegate_AddFamily(hTPM, 'a', &hFamily);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_TPM_Delegate_AddFamily", (result) );
		goto done;
	}

	result = Tspi_SetAttribUint32(hFamily, TSS_TSPATTRIB_DELFAMILY_STATE,
			TSS_TSPATTRIB_DELFAMILYSTATE_ENABLED, TRUE);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_SetAttribUint32", (result) );
		goto done;
	}

	result = Tspi_TPM_Delegate_CreateDelegation(hTPM, 'b', 0, NULL_HPCRS, hFamily, hDelegation1);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_TPM_Delegate_CreateDelegation", (result) );
		goto done;
	}

	// This Verify should succeed since verification count hasn't been changed
	result = Tspi_TPM_Delegate_VerifyDelegation(hDelegation1);
	if ( result != TSS_SUCCESS )
	{
		print_error( function, (result) );
		goto done;
	}

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hDelegation2);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject", (result) );
		goto done;
	}

	result = Tspi_Policy_SetSecret( hDelegation2, TESTSUITE_DELEGATE_SECRET_MODE,
					TESTSUITE_DELEGATE_SECRET_LEN, TESTSUITE_DELEGATE_SECRET );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		goto done;
	}

	result = Tspi_SetAttribUint32(hDelegation2, TSS_TSPATTRIB_POLICY_DELEGATION_INFO,
			TSS_TSPATTRIB_POLDEL_TYPE, TSS_DELEGATIONTYPE_OWNER);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_SetAttribUint32", (result) );
		goto done;
	}

	result = Tspi_SetAttribUint32(hDelegation2, TSS_TSPATTRIB_POLICY_DELEGATION_INFO,
			TSS_TSPATTRIB_POLDEL_PER1, 0);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_SetAttribUint32", (result) );
		goto done;
	}

	result = Tspi_SetAttribUint32(hDelegation2, TSS_TSPATTRIB_POLICY_DELEGATION_INFO,
			TSS_TSPATTRIB_POLDEL_PER2, 0);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_SetAttribUint32", (result) );
		goto done;
	}

	result = Tspi_TPM_Delegate_CreateDelegation(hTPM, 'b', TSS_DELEGATE_INCREMENTVERIFICATIONCOUNT,
			NULL_HPCRS, hFamily, hDelegation2);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_TPM_Delegate_CreateDelegation", (result) );
		goto done;
	}

	result = Tspi_TPM_Delegate_VerifyDelegation(hDelegation1);
	if ( TSS_ERROR_CODE( result ) != TPM_E_FAMILYCOUNT )
	{
		print_error( "Tspi_TPM_Delegate_VerifyDelegation", (result) );
		goto done;
	}

	result = Testsuite_Transport_Final(hContext, hSigningKey);
	if ( result == TSS_SUCCESS )
	{
		print_error( "Testsuite_Transport_Final", (result) );
		goto done;
	}
	else
	{
		print_success( function, result );
	}

	print_end_test( function );
done:
	/* Invalidate the family to avoid resource exhaustion */
	if (hFamily != NULL_HDELFAMILY)
		Tspi_TPM_Delegate_InvalidateFamily(hTPM, hFamily);
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );

	exit( result );
}
