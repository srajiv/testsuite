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
 *	Tspi_Context_UnregisterKey01.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_Context_UnregisterKey
 *	The point of this test case is to get TSS_SUCCESS 
 *		to be returned. 
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		GetTPMObject
 *		Create Object
 *		LoadKeyByUUID
 *		Get Policy Object (srk)
 *		Set Secret (srk)
 *		Get Policy Object (key, x2)
 *		Set Secret (key, x2)
 *		Create Key
 *		SetAttribUint32 (x2)
 *		RegisterKey
 *
 *	Test:	Call UnregisterKey. If this is unsuccessful check for 
 *		type of error, and make sure it returns the proper return code
 * 
 *	Cleanup:
 *		Free memory associated with the context
 *		Close the hKey object
 *		Close context
 *		Print error/success message.
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

int
main_v1_1(void){

	char		*nameOfFunction = "Tspi_Context_UnregisterKey01";
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_FLAG	initFlags;
	TSS_HKEY	hKey;
	TSS_HKEY	hSRK;
	TSS_RESULT	result;
	TSS_UUID	migratableSignUUID = {1, 2, 3, 4, 5, {6, 7, 8, 9, 10, 2}};
	TSS_HPOLICY	srkUsagePolicy, keyUsagePolicy, keyMigPolicy;
	initFlags	= TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048  |
			TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
			TSS_KEY_NOT_MIGRATABLE;
	BYTE		well_known_secret[20] = TSS_WELL_KNOWN_SECRET;

	print_begin_test(nameOfFunction);

		//Create
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
		//Connect
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get TPM Object
	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetTpmObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Create Object
	result = Tspi_Context_CreateObject(hContext,
				TSS_OBJECT_TYPE_RSAKEY,
				initFlags, &hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Load Key by UUID
	result = Tspi_Context_LoadKeyByUUID(hContext, 
						TSS_PS_TYPE_SYSTEM, 
						SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get Policy Object for the srkUsagePolicy
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret for the srkUsagePolicy
	result = Tspi_Policy_SetSecret(srkUsagePolicy, TSS_SECRET_MODE_PLAIN,
			0, NULL);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret ", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
		//Get Policy Object for the keyUsagePolicy
	result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &keyUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get Policy Object for the keyMigPolicy
	result = Tspi_GetPolicyObject(hKey, TSS_POLICY_MIGRATION, &keyMigPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret 
	result = Tspi_Policy_SetSecret(keyMigPolicy, 
					TSS_SECRET_MODE_SHA1, 
					20, well_known_secret);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret
	result = Tspi_Policy_SetSecret(keyUsagePolicy, 
					TSS_SECRET_MODE_SHA1, 
					20, well_known_secret);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Create the hKey with the hSRK wrapping key
	result = Tspi_Key_CreateKey(hKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//SetAttribUint32
	result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
				TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
				TSS_ES_NONE);
	if (result != TSS_SUCCESS) { 
		print_error("Tspi_SetAttribUint32 ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//SetAttribUint32
	result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
				TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
				TSS_ES_NONE);
	if (result != TSS_SUCCESS) { 
		print_error("Tspi_SetAttribUint32 ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Register the hKey
	result = Tspi_Context_RegisterKey(hContext,
				hKey, TSS_PS_TYPE_SYSTEM, migratableSignUUID,
				TSS_PS_TYPE_SYSTEM, SRK_UUID);
	if (result != TSS_SUCCESS && TSS_ERROR_CODE(result) != TSS_E_KEY_ALREADY_REGISTERED) {
		print_error("Tspi_Context_RegisterKey ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//UnregisterKey
	result = Tspi_Context_UnregisterKey(hContext, 
					TSS_PS_TYPE_SYSTEM,
					migratableSignUUID, &hKey);
	if (result != TSS_SUCCESS) {
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			exit(result);
		}
		else{
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}
	else{
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
