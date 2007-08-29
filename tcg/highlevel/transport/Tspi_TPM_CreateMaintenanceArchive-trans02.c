/*
 *
 *   Copyright (C) International Business Machines  Corp., 2004-2006
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
 *	Tspi_TPM_CreateMaintenanceArchive01.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_TPM_CreateMaintenanceArchive succeeds.
 *
 *	There are 3 acceptable return codes from this API:
 *	TSS_SUCCESS: The TPM supports this command and it succeeded.
 *	TCPA_E_DISABLED_CMD: The testsuite or user has run the kill
 *	                     maintenance feature API on this TPM
 *	TCPA_E_INACTIVE: The TPM doesn't support this API (most likely)
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Get TPM Object
 *
 *	Test:
 *		Call TPM_CreateMaintenanceArchive then if it does not succeed
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
 *      Megan Schneider, mschnei@us.ibm.com, 6/04.
 *      Kent Yoder, kyoder@users.sf.net, 5/06.
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
	if (version == TESTSUITE_TEST_TSS_1_2)
		main_v1_2(version);
	else if (version == TESTSUITE_TEST_TSS_1_1)
		print_NA();
	else
		print_wrongVersion();
}

int
main_v1_2(char version)
{
	char		*function = "Tspi_TPM_CreateMaintenanceArchive-trans02";
	TSS_HCONTEXT	hContext;
	TSS_HPOLICY	hTPMPolicy;
	TSS_HTPM	hTPM;
	UINT32		pulOneTimePadLength;
	BYTE		*pOneTimePad;
	UINT32		pulArchiveDataLength;
	BYTE		*pArchiveData;
	TSS_RESULT	result;
	TSS_HKEY	hSigningKey, hWrappingKey, hSRK;

	print_begin_test( function );

	result = connect_load_all(&hContext, &hSRK, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("connect_load_all", result);
		print_error_exit(function, err_string(result));
		exit(result);
	}

	result = Testsuite_Transport_Init(hContext, hSRK, hTPM, TRUE, TRUE, &hWrappingKey,
					  &hSigningKey);
	if (result != TSS_SUCCESS) {
		print_error("Testsuite_Transport_Init", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Insert the owner auth into the TPM's policy
	result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTPMPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Policy_SetSecret(hTPMPolicy, TESTSUITE_OWNER_SECRET_MODE,
				       TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		//Get random number
	result = Tspi_TPM_CreateMaintenanceArchive( hTPM, TRUE,
						&pulOneTimePadLength,
						&pOneTimePad,
						&pulArchiveDataLength,
						&pArchiveData );
	if (result != TSS_SUCCESS &&
	    TSS_ERROR_CODE(result) != TCPA_E_INACTIVE &&
	    TSS_ERROR_CODE(result) != TCPA_E_DISABLED_CMD)
	{
		print_error("Tspi_TPM_CreateMaintenanceArchive", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	if (!result) {
		result = Tspi_Context_FreeMemory(hContext, pArchiveData);
		result |= Tspi_Context_FreeMemory(hContext, pOneTimePad);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Context_FreeMemory ", result);
			print_error_exit(function, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}

	result = Testsuite_Transport_Final(hContext, hSigningKey);
	if (result != TSS_SUCCESS)
	{
		if( !(checkNonAPI(result)) )
		{
			print_error( function, result );
		}
		else
		{
			print_error_nonapi( function, result );
		}

		print_end_test( function );
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
