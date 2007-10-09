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
 *	Tspi_TPM_KeyControlOwner01.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_TPM_KeyControlOwner.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context 
 *		Create Object (to hold new key)
 *		Get TPM Object
 *		Get TPM policy
 *		Set Owner Secret
 *		Get SRK Key
 *		Set SRK Secret
 *		Create Key (parent = SRK)
 *		Load newly created Key
 *	Test:
 *		Call KeyControlOwner, set the owner evict bit
 *		Call KeyControlOwner, unset the owner evict bit
 *
 *	Cleanup:
 *		Unload Key
 *		Free context memory
 *		Close context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *
 * HISTORY
 *	Author:	Klaus Heinrich Kiwi
 *	Date:	August 2007
 *	Email:	klausk@br.ibm.com
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

	char		*nameOfFunction = "Tspi_TPM_KeyControlOwner01";
	TSS_RESULT	result;
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_FLAG	initFlags;
	TSS_HKEY	hSRK;
	TSS_HKEY	hKey;
	TSS_HKEY	hTargetPubKey;
	TSS_HPOLICY	hTpmPolicy, hSrkPolicy;
	TSS_UUID	Uuid;

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
		Tspi_Context_FreeMemory( hContext, NULL );
		exit(result);
	}

		//Create Object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
					   TSS_KEY_SIZE_2048 |
					   TSS_KEY_TYPE_SIGNING, &hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Get TPM Object
	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetTpmObject", result);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Requires Owner auth - get policy
	result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTpmPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject ", result);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Set Owner Secret
	result = Tspi_Policy_SetSecret(hTpmPolicy, TESTSUITE_OWNER_SECRET_MODE,
				       TESTSUITE_OWNER_SECRET_LEN,
				       TESTSUITE_OWNER_SECRET );
	if ( result != TSS_SUCCESS )
	{
		print_error("Tspi_Policy_SetSecret (Owner)", result);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Get SRK Key
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID ", result);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Requires SRK auth - get policy
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSrkPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject ", result);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Set SRK Secret
	result = Tspi_Policy_SetSecret(hSrkPolicy, TESTSUITE_SRK_SECRET_MODE,
				       TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET );
	if ( result != TSS_SUCCESS )
	{
		print_error("Tspi_Policy_SetSecret (Owner)", result);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Create Key
	result = Tspi_Key_CreateKey(hKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Load key
	result = Tspi_Key_LoadKey(hKey, hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_LoadKey", result);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Set Ownerevict bit
	result = Tspi_TPM_KeyControlOwner(hTPM, hKey, TSS_TSPATTRIB_KEYCONTROL_OWNEREVICT,
					  TRUE, &Uuid);
	if (result != TSS_SUCCESS) {
		print_error(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close(hContext);
		exit(result);
	} else {
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
