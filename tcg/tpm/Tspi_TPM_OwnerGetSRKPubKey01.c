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
 *	Tspi_TPM_OwnerGetSRKPubKey01.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_TPM_OwnerGetSRKPubKey.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context 
 *		Get TPM Object
 *	Test:
 *		Call OwnerGetSRKPubKey and make sure it is a success
 *
 *	Cleanup:
 *		Close context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *
 * HISTORY
 *	Author:	Loulwa Salem
 *	Date:	July 2007
 *	Email:	loulwa@us.ibm.com
 *
 * RESTRICTIONS
 *	None.
 */

#include "common.h"

int main(int argc, char **argv)
{
	char version;

	version = parseArgs( argc, argv );
	if (version == TESTSUITE_TEST_TSS_1_2)
		main_v1_2(version);
	else
		print_NA();
}

main_v1_2(char version){

	char		*nameOfFunction = "Tspi_TPM_OwnerGetSRKPubKey01";
	TSS_RESULT	result;
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_HKEY	hSRK;
	TSS_HPOLICY	hPolicy;
	UINT32          pulPubKeyLength;
	BYTE            *prgbPubKey;

	print_begin_test(nameOfFunction);

		//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create", result);
		exit(result);
	}
		//Connect Context
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		exit(result);
	}
		//Get TPM Object
	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetTpmObject", result);
		exit(result);
	}

		//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_GetPolicyObject( hTPM, TSS_POLICY_USAGE, &hPolicy );
	if ( result != TSS_SUCCESS ) {
		print_error( "Tspi_GetPolicyObject", result );
		return result;
	}

	result = Tspi_Policy_SetSecret( hPolicy, TESTSUITE_OWNER_SECRET_MODE,
					TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);
	if ( result != TSS_SUCCESS ) {
		print_error( "Tspi_Policy_SetSecret", result );
		return result;
	}

		//Get SRK Public Key
	result = Tspi_TPM_OwnerGetSRKPubKey(hTPM, &pulPubKeyLength, &prgbPubKey);
	if (result != TSS_SUCCESS) {
		print_error(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(result);
	} else {
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
