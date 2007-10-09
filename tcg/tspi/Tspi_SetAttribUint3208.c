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
 *	Tspi_SetAttribUint3208.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_SetAttribUint32 for ordinal auditing
 *		returns TSS_SUCCESS.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Get TPM Handle
 *
 *	Test:
 *		Call SetAttribUint32.
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
	char *		function = "Tspi_SetAttribUint3208";
	TSS_HCONTEXT	hContext;
	TSS_HKEY	hSRK;
	TSS_HTPM	hTPM;
	TSS_HPOLICY	hTpmPolicy;
	UINT32		ordinal = TPM_ORD_CreateWrapKey, subCap, pulRespLen;
	TSS_RESULT	result;
	BYTE*		prgbRespData;

	print_begin_test( function );

	result = connect_load_all(&hContext, &hSRK, &hTPM);
	if ( result != TSS_SUCCESS )
	{
		print_error( "connect_load_all", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hTpmPolicy);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_createObject", result );
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

	result = Tspi_Policy_AssignToObject(hTpmPolicy, hTPM);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_AssignToObject", result );
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

		//Call SetAttribUint32
	result = Tspi_SetAttribUint32(hTPM,
			TSS_TSPATTRIB_TPM_ORDINAL_AUDIT_STATUS,
			TPM_CAP_PROP_TPM_SET_ORDINAL_AUDIT,
			ordinal);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_SetAttribUint32", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		//Call SetAttribUint32
	result = Tspi_SetAttribUint32(hTPM,
			TSS_TSPATTRIB_TPM_ORDINAL_AUDIT_STATUS,
			TPM_CAP_PROP_TPM_CLEAR_ORDINAL_AUDIT,
			ordinal);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_SetAttribUint32", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	else
	{
		print_success( function, result );
	}

	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( 0 );
}
