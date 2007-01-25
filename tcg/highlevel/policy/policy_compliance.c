/*
 *
 *   Copyright (C) International Business Machines  Corp., 2004-2007
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
 *	policy_compliance.c
 *
 * DESCRIPTION
 *	This test will verify that various aspects of policy work correctly.
 *
 * ALGORITHM
 *	Setup:
 *
 *	Test:
 *
 *	Cleanup:
 *
 * USAGE
 *      First parameter is --options
 *                         -v or --version
 *      Second parameter is the version of the test case to be run
 *      This test case is currently only implemented for v1.1
 *
 * HISTORY
 *	Kent Yoder 01/07
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
	char			*function = "policy_compliance";
	TSS_RESULT		result;
	TSS_HPOLICY		hDefaultPolicy, hKeyUsagePolicy, hKeyMigPolicy;
	TSS_HPOLICY		hEncdataUsagePolicy, hTPMPolicy, hNewPolicy;
	TSS_HCONTEXT		hContext;
	TSS_HKEY		hKey;
	TSS_HENCDATA		hEncData;
	TSS_HTPM		hTPM;
	TSS_HPCRS		hPcrs;
	TSS_HHASH		hHash;
	UINT32			trash;

	print_begin_test( function );

		// Create Context
	result = Tspi_Context_Create( &hContext );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Create", result );
		print_error_exit( function, err_string(result) );
		exit( result );
	}

	/*
	 * Test 1
	 *
	 * TSP's default policy object should exist.
	 *
	 */
	result = Tspi_Context_GetDefaultPolicy ( hContext, &hDefaultPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Test 1: TSP object's default policy should exist", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 1", result );

	/*
	 * Test 2
	 *
	 * Create a key, then get its usage policy handle. It should match
	 * the TSP's default policy.
	 *
	 */
	result = Tspi_Context_CreateObject ( hContext,
					     TSS_OBJECT_TYPE_RSAKEY,
					     TSS_KEY_TYPE_SIGNING |
					     TSS_KEY_SIZE_512 |
					     TSS_KEY_NO_AUTHORIZATION |
					     TSS_KEY_MIGRATABLE,
					     &hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hKeyUsagePolicy);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	if (hKeyUsagePolicy != hDefaultPolicy) {
		print_error( "Test 2: default policy should match new policies", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 2", result );

	/*
	 * Test 3
	 *
	 * The key should have no migration policy by default.
	 *
	 */
	result = Tspi_GetPolicyObject(hKey, TSS_POLICY_MIGRATION, &hKeyMigPolicy);
	if ( TSS_ERROR_CODE(result) != TSS_E_KEY_NO_MIGRATION_POLICY )
	{
		print_error( "Test 3: Key's migration policy shouldn't exist by default", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 3", result );

	/*
	 * Test 4
	 *
	 * Create an encdata object, then get its usage policy handle. It should match
	 * the TSP's default policy.
	 *
	 */
	result = Tspi_Context_CreateObject ( hContext,
					     TSS_OBJECT_TYPE_ENCDATA,
					     TSS_ENCDATA_BIND,
					     &hEncData );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_GetPolicyObject(hEncData, TSS_POLICY_USAGE, &hEncdataUsagePolicy);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	if (hEncdataUsagePolicy != hDefaultPolicy) {
		print_error( "Test 4: default policy should match new policies", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 4", result );

	/*
	 * Test 5
	 *
	 * Connect the TSP context to a TCS and get the TPM object, then its policy. It should
	 * not match the TSP's default policy.
	 *
	 */
		// Connect to Context
	result = Tspi_Context_Connect( hContext, get_server(GLOBALSERVER) );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Connect", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_GetTpmObject( hContext, &hTPM );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_GetTpmObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTPMPolicy);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	if (hTPMPolicy == hDefaultPolicy) {
		print_error( "Test 5: default policy should not match the TPM policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 5", result );

	/*
	 * Test 6
	 *
	 * Create a new policy object. Its handle should not match the TSP's default policy or
	 * the TPM's policy.
	 *
	 */
	result = Tspi_Context_CreateObject ( hContext,
					     TSS_OBJECT_TYPE_POLICY,
					     TSS_POLICY_MIGRATION,
					     &hNewPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	if (hNewPolicy == hTPMPolicy || hNewPolicy == hDefaultPolicy) {
		print_error( "Test 6: new policy should not match any other policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 6", result );

	/*
	 * Test 7
	 *
	 * Assign the policy object as the key's migration policy. After this, the key should have
	 * a migration policy.
	 *
	 */
	result = Tspi_Policy_AssignToObject( hNewPolicy, hKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_AssignToObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_GetPolicyObject(hKey, TSS_POLICY_MIGRATION, &hKeyMigPolicy);
	if ( result != TSS_SUCCESS || hKeyMigPolicy != hNewPolicy)
	{
		print_error( "Test 7: Key's migration policy should match new policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 7", result );

	/*
	 * Test 8
	 *
	 * Try to get a migration policy for the TPM
	 *
	 */
	result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_MIGRATION, &trash);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER)
	{
		print_error( "Test 8: TPM should have no migration policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 8", result );

	/*
	 * Test 9
	 *
	 * Try to get a migration policy for enc data
	 *
	 */
	result = Tspi_GetPolicyObject(hEncData, TSS_POLICY_MIGRATION, &trash);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER)
	{
		print_error( "Test 9: Encdata should have no migration policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 9", result );

	/*
	 * Test 10
	 *
	 * Try to get a migration policy for a hash object
	 *
	 */
	result = Tspi_Context_CreateObject ( hContext,
					     TSS_OBJECT_TYPE_HASH,
					     TSS_HASH_OTHER,
					     &hHash );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_GetPolicyObject(hHash, TSS_POLICY_MIGRATION, &trash);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER)
	{
		print_error( "Test 10: Hash should have no migration policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 10", result );

	/*
	 * Test 11
	 *
	 * Try to get a usage policy for a hash object
	 *
	 */
	result = Tspi_GetPolicyObject(hHash, TSS_POLICY_USAGE, &trash);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER)
	{
		print_error( "Test 11: Hash should have no usage policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 11", result );

	/*
	 * Test 12
	 *
	 * Try to get a migration policy for a pcrs object
	 *
	 */
	result = Tspi_Context_CreateObject ( hContext,
					     TSS_OBJECT_TYPE_PCRS,
					     0,
					     &hPcrs );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_GetPolicyObject(hPcrs, TSS_POLICY_MIGRATION, &trash);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER)
	{
		print_error( "Test 12: Pcrs should have no migration policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 12", result );

	/*
	 * Test 13
	 *
	 * Try to get a usage policy for a pcrs object
	 *
	 */
	result = Tspi_GetPolicyObject(hPcrs, TSS_POLICY_USAGE, &trash);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER)
	{
		print_error( "Test 13: Pcrs should have no usage policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 13", result );

	/*
	 * Test 14
	 *
	 * Try to get a migration policy for a policy object
	 *
	 */
	result = Tspi_GetPolicyObject(hEncdataUsagePolicy, TSS_POLICY_MIGRATION, &trash);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER)
	{
		print_error( "Test 14: Policies should have no migration policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 14", result );

	/*
	 * Test 15
	 *
	 * Try to get a usage policy for a policy object
	 *
	 */
	result = Tspi_GetPolicyObject(hEncdataUsagePolicy, TSS_POLICY_USAGE, &trash);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER)
	{
		print_error( "Test 15: Policies should have no usage policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 15", result );

	/*
	 * Test 16
	 *
	 * Try to get a migration policy for a context object
	 *
	 */
	result = Tspi_GetPolicyObject(hContext, TSS_POLICY_MIGRATION, &trash);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER)
	{
		print_error( "Test 16: Contexts should have no migration policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 16", result );

	/*
	 * Test 17
	 *
	 * Try to get a usage policy for a context object
	 *
	 */
	result = Tspi_GetPolicyObject(hContext, TSS_POLICY_USAGE, &trash);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER)
	{
		print_error( "Test 17: Context's policies should not be accessible by "
			     "Tspi_GetPolicyObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 17", result );



	/*
	 * Test 18
	 *
	 * Try to assign a migration policy for the TPM
	 *
	 */
	result = Tspi_Policy_AssignToObject(hKeyMigPolicy, hTPM);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER )
	{
		print_error( "Test 18: TPM should not be assigned a migration policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 18", result );

	/*
	 * Test 19
	 *
	 * Try to assign a migration policy for enc data
	 *
	 */
	result = Tspi_Policy_AssignToObject(hKeyMigPolicy, hEncData);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER )
	{
		print_error( "Test 19: Encdata should not be assigned a migration policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 19", result );

	/*
	 * Test 20
	 *
	 * Try to assign a migration policy to a hash object
	 *
	 */
	result = Tspi_Policy_AssignToObject(hKeyMigPolicy, hHash);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER )
	{
		print_error( "Test 20: Hash should not be assigned a migration policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 20", result );

	/*
	 * Test 21
	 *
	 * Try to assign a usage policy for a hash object
	 *
	 */
	result = Tspi_Policy_AssignToObject(hKeyUsagePolicy, hHash);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER)
	{
		print_error( "Test 21: Hash should not be assigned a usage policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 21", result );

	/*
	 * Test 22
	 *
	 * Try to assign a migration policy for a pcrs object
	 *
	 */
	result = Tspi_Policy_AssignToObject(hKeyMigPolicy, hPcrs);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER )
	{
		print_error( "Test 22: Pcrs should not be assigned a migration policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 22", result );

	/*
	 * Test 23
	 *
	 * Try to assign a usage policy for a pcrs object
	 *
	 */
	result = Tspi_Policy_AssignToObject(hKeyUsagePolicy, hPcrs);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER )
	{
		print_error( "Test 23: Pcrs should not be assigned a usage policy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 23", result );

	/*
	 * Test 24
	 *
	 * Try to assign a migration policy for a policy object
	 *
	 */
	result = Tspi_Policy_AssignToObject(hKeyMigPolicy, hKeyUsagePolicy);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER )
	{
		print_error( "Test 24: Policies should not be assigned migration policies",
			     result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 24", result );

	/*
	 * Test 25
	 *
	 * Try to assign a usage policy for a policy object
	 *
	 */
	result = Tspi_Policy_AssignToObject(hKeyUsagePolicy, hEncdataUsagePolicy);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER )
	{
		print_error( "Test 25: Policies should not be assigned usage policies", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 25", result );

	/*
	 * Test 26
	 *
	 * Try to assign a migration policy for a context object
	 *
	 */
	result = Tspi_Policy_AssignToObject(hKeyMigPolicy, hContext);
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER )
	{
		print_error( "Test 26: Contexts should not be assigned migration policies",
			     result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 26", result );

	/*
	 * Test 27
	 *
	 * Close hKey's usage policy and make sure getPolicyObject returns correctly
	 *
	 */
	result = Tspi_Context_CloseObject(hContext, hKeyUsagePolicy);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CloseObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &hNewPolicy);
	if ( TSS_ERROR_CODE(result) != TSS_E_INTERNAL_ERROR )
	{
		print_error( "Test 27: Accessing a closed policy should trigger"
			     " TSS_E_INTERNAL_ERROR", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	} else
		print_success( "Test 27", result );


	print_success(function, TSS_SUCCESS);
	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( 0 );
}
