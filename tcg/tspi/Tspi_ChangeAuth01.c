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
 *	Tspi_ChangeAuth01
 *
 * DESCRIPTION
 *	This test will verify Tspi_ChangeAuth
 *	The goal of this test is to return TSS_SUCCESS.
 *		To have it return success, you need to follow the
 *		algorithm described below.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect
 *		Create hKeyChild
 *		Load Key By UUID for hSRK
 *		Get Policy Object for the srk
 *		Set Secret
 *		Create Storage Key
 *		Create Signing Key
 *		Load keys
 *		Get Default Policy for the hPolicy
 *
 *	Test:	Call ChangeAuth. If it is not a success
 *		Make sure that it returns the proper return codes
 *
 *	Cleanup:
 *		Free memory associated with the context
 *		Close hMSigningKey Object
 *		Close hKeyChild Object
 *		Close context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1
 *
 * HISTORY
 *	Author:	Kathy Robertson
 *	Date:	June 2004
 *	Email:	klrobert@us.ibm.com
 *
 * RESTRICTIONS
 *	None.
 */

#include <trousers/tss.h>
#include "../common/common.h"



int main(int argc, char **argv)
{
	char		*version;

	version = parseArgs( argc, argv );
		// if it is not version 1.1, print error
	if(strcmp(version, "1.1")){
		print_wrongVersion();
	}
	else{
		main_v1_1();
	}
}

main_v1_1(void){

	char		*nameOfFunction = "Tspi_ChangeAuth01";
	TSS_HKEY	hKeyChild, hKeyParent, hSRK;
	TSS_HPOLICY	srkUsagePolicy, hKeyChildPolicy, hKeyParentPolicy, hNewPolicy;
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_FLAG	initFlags;
	initFlags	= TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048  |
			TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION |
			TSS_KEY_NOT_MIGRATABLE;

	print_begin_test(nameOfFunction);

		//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
		//Connect Context
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}


	// Set up the SRK

		//Load SRK By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext,
			TSS_PS_TYPE_SYSTEM,
			SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID for hSRK", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get Policy Object
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret
	result = Tspi_Policy_SetSecret(srkUsagePolicy, TESTSUITE_SRK_SECRET_MODE,
				TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}


	// Create Parent Key (no auth, storage)

#if 0
#if 1
		//Create Storage Key
	result = Tspi_Context_CreateObject(hContext,
			TSS_OBJECT_TYPE_RSAKEY,
			TSS_KEY_SIZE_2048 | TSS_KEY_TYPE_STORAGE |
			TSS_KEY_NO_AUTHORIZATION,
			&hKeyParent);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Key_CreateKey(hKeyParent, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Key_LoadKey(hKeyParent, hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_LoadKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
#else
		//Create auth'd Storage Key
	result = Tspi_Context_CreateObject(hContext,
			TSS_OBJECT_TYPE_RSAKEY,
			TSS_KEY_SIZE_2048 | TSS_KEY_TYPE_STORAGE |
			TSS_KEY_AUTHORIZATION,
			&hKeyParent);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		// Get existing Policy Object
	result = Tspi_GetPolicyObject(hKeyParent, TSS_POLICY_USAGE, &hKeyParentPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		// Set Secret
	result = Tspi_Policy_SetSecret(hKeyParentPolicy, TESTSUITE_KEY_SECRET_MODE,
				       TESTSUITE_KEY_SECRET_LEN, TESTSUITE_KEY_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_CreateKey(hKeyParent, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Key_LoadKey(hKeyParent, hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_LoadKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
#endif
#endif
	// Set up Child Key (signing, auth)

	hKeyParent = hSRK;

		//Create Object for Child Key
	result = Tspi_Context_CreateObject(hContext,
			TSS_OBJECT_TYPE_RSAKEY,
			TSS_KEY_SIZE_2048 | TSS_KEY_TYPE_SIGNING |
			TSS_KEY_AUTHORIZATION,
			&hKeyChild);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKeyChild);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Get existing Policy Object
	result = Tspi_GetPolicyObject(hKeyChild, TSS_POLICY_USAGE, &hKeyChildPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		// Set Secret
	result = Tspi_Policy_SetSecret(hKeyChildPolicy, TESTSUITE_KEY_SECRET_MODE,
				       TESTSUITE_KEY_SECRET_LEN, TESTSUITE_KEY_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_CreateKey(hKeyChild, hKeyParent, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_LoadKey(hKeyChild, hKeyParent);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_LoadKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}




		// create a new Policy
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
					TSS_POLICY_USAGE, &hNewPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetPolicy ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Set the new policy's Secret
	result = Tspi_Policy_SetSecret(hNewPolicy, TESTSUITE_NEW_SECRET_MODE,
				       TESTSUITE_NEW_SECRET_LEN, TESTSUITE_NEW_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Call Change Auth
	result = Tspi_ChangeAuth(hKeyChild, hKeyParent, hNewPolicy);
	if (result != TSS_SUCCESS) {
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_Close(hContext);
			exit(result);
		}
		else{
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}
	else{
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
