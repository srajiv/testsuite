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
 *	Tspi_ChangeAuth03
 *
 * DESCRIPTION
 *	This test will verify Tspi_ChangeAuth.
 *	The purpose of this test case is to get TSS_E_INVALID_HANDLE
 *		to be returned. This is easily accomplished by passing 
 *		in an inccorect first parameter. In this test case
 *		passes in -1 for the first parameter. 
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect
 *		Create hKey
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
 *		Close hMStorageKey Object
 *		Close hKey Object
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

	char		*nameOfFunction = "Tspi_ChangeAuth03";
	TSS_HKEY	hKey;
	TSS_HKEY	hSRK;
	TSS_HPOLICY	hPolicy;
	TSS_HKEY	hMSigningKey;
	TSS_HKEY	hMStorageKey;
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_FLAG	initFlags;
	initFlags	= TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048  |
			TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
			TSS_KEY_NOT_MIGRATABLE;
	TSS_HPOLICY	srkUsagePolicy;

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
		//Create hKey
	result = Tspi_Context_CreateObject(hContext,
			TSS_OBJECT_TYPE_RSAKEY,
			initFlags, &hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext,
			TSS_PS_TYPE_SYSTEM,
			SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID for hSRK", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
#ifndef TESTSUITE_NOAUTH_SRK
		//Get Policy Object
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret
	result = Tspi_Policy_SetSecret(srkUsagePolicy, TESTSUITE_SRK_SECRET_MODE,
				TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
#endif
		//Create Storage Key
	result = Tspi_Context_CreateObject(hContext, 
			TSS_OBJECT_TYPE_RSAKEY,
			TSS_KEY_SIZE_2048 |TSS_KEY_TYPE_SIGNING 
			|TSS_KEY_MIGRATABLE, &hMStorageKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Key_CreateKey(hMStorageKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hMStorageKey);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Create Object for Signing Key
	result = Tspi_Context_CreateObject(hContext, 
			TSS_OBJECT_TYPE_RSAKEY,
			TSS_KEY_SIZE_2048 |TSS_KEY_TYPE_SIGNING 
			|TSS_KEY_MIGRATABLE, &hMSigningKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hMStorageKey);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Create Key for hMSigning Key
	result = Tspi_Key_CreateKey(hMSigningKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hMSigningKey);
		Tspi_Context_CloseObject(hContext, hMStorageKey);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get Default Policy
	result = Tspi_Context_GetDefaultPolicy(hContext, &hPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetPolicy ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hMSigningKey);
		Tspi_Context_CloseObject(hContext, hMStorageKey);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Call Change Auth
	result = Tspi_ChangeAuth(-1, hMStorageKey, hPolicy);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_HANDLE) {
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, hMSigningKey);
			Tspi_Context_CloseObject(hContext, hMStorageKey);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			exit(result);
		}
		else{
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, hMSigningKey);
			Tspi_Context_CloseObject(hContext, hMStorageKey);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}
	else{
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_CloseObject(hContext, hMSigningKey);
		Tspi_Context_CloseObject(hContext, hMStorageKey);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
