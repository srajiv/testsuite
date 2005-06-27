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
 *	Tspi_Key_CertifyKey02
3
 *
 * DESCRIPTION
 *	This test will verify Tspi_Key_CertifyKey
 *	The purpose of this test case is to get TSS_E_INVALID_HANDLE
 *		which is accomplished by passin in an incorrct second
 *		parameter. For this test case, -1 is passed in for the
 *		second parameter.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect
 *		Get TPM Object
 *		Create hKey
 *		Load Key By UUID for hSRK
 *		Get Policy Object for the srk
 *		Set Secret for srk
 *		Get Policy Object for TPM
 *		Set Secret for tpm
 *		Create Ident Key Object
 *		Get Policy Object
 *		Set Secret
 *		Create Key
 *		Load Key
 *		Create NonMigratableSigning Key Object
 *		Get Policy Object
 *		Set Secret
 *		Create Key
 *		Load Key
 *		Get Default Policy for the hPolicy
 *		Get Random
 *		Set Validation data
 *
 *	Test:	Call CertifyKey. If it is not a success
 *		Make sure that it returns the proper return codes
 *
 *	Cleanup:
 *		Free memory associated with the context
 *		Close the NonMigratableSigningKey object
 *		Close the hIdentKey object
 *		Close the hKey object
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

	char		*nameOfFunction = "Tspi_Key_CertifyKey02";
	TSS_HKEY	hKey;
	TSS_HKEY	hSRK;
	TSS_HPOLICY	hPolicy;
	TSS_HKEY	NonMigratableSigningKey;
	TSS_HKEY	hIdentKey;
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_FLAG	initFlags;
	TSS_HPOLICY	srkUsagePolicy, keyUsagePolicy;
	TSS_VALIDATION	pValidationData;
	BYTE		*data;
	TSS_HTPM	hTPM;
	BYTE		well_known_secret[] = TSS_WELL_KNOWN_SECRET;
	initFlags	= TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048  |
			TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
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
		//Get TPM Object
	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetTpmObject", result);
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
		print_error("Tspi_Context_LoadKeyByUUID", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		Tspi_Context_CloseObject(hContext, hKey);
		exit(result);
	}
		//Get Policy Object
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		Tspi_Context_CloseObject(hContext, hKey);
		exit(result);
	}
		//Set Secret
	result = Tspi_Policy_SetSecret(srkUsagePolicy, TSS_SECRET_MODE_PLAIN,
				0, NULL);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		Tspi_Context_CloseObject(hContext, hKey);
		exit(result);
	}
	result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE,
					&keyUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret
	result = Tspi_Policy_SetSecret(keyUsagePolicy,
				TSS_SECRET_MODE_PLAIN,
				20, well_known_secret);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Create Object for Ident Key
	result = Tspi_Context_CreateObject(hContext, 
			TSS_OBJECT_TYPE_RSAKEY,
			TSS_KEY_SIZE_2048 |TSS_KEY_TYPE_SIGNING 
			|TSS_KEY_MIGRATABLE, &hIdentKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		Tspi_Context_CloseObject(hContext, hKey);
		exit(result);
	}
	result = Tspi_GetPolicyObject(hIdentKey, TSS_POLICY_USAGE,
					&keyUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret
	result = Tspi_Policy_SetSecret(keyUsagePolicy,
				TSS_SECRET_MODE_PLAIN,
				20, well_known_secret);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Create Key for Ident Key
	result = Tspi_Key_CreateKey(hIdentKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_CloseObject(hContext, hIdentKey);
		exit(result);
	}
		//Create Object for NonMigratableSigningKey
	result = Tspi_Context_CreateObject(hContext, 
			TSS_OBJECT_TYPE_RSAKEY,
			TSS_KEY_SIZE_2048 |TSS_KEY_TYPE_SIGNING 
			|TSS_KEY_MIGRATABLE, &NonMigratableSigningKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_CloseObject(hContext, hIdentKey);
		exit(result);
	}
	result = Tspi_GetPolicyObject(NonMigratableSigningKey, TSS_POLICY_USAGE,
					&keyUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret
	result = Tspi_Policy_SetSecret(keyUsagePolicy,
				TSS_SECRET_MODE_PLAIN,
				20, well_known_secret);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Create Key for NonMigratableSigningKey
	result = Tspi_Key_CreateKey(NonMigratableSigningKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_CloseObject(hContext, NonMigratableSigningKey);
		Tspi_Context_CloseObject(hContext, hIdentKey);
		exit(result);
	}
		//Get Default Policy
	result = Tspi_Context_GetDefaultPolicy(hContext, &hPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetPolicy ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		Tspi_Context_CloseObject(hContext, NonMigratableSigningKey);
		Tspi_Context_CloseObject(hContext, hIdentKey);
		Tspi_Context_CloseObject(hContext, hKey);
		exit(result);
	}
	result = Tspi_TPM_GetRandom(hTPM, 20, &data);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_GetRandom ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		Tspi_Context_CloseObject(hContext, NonMigratableSigningKey);
		Tspi_Context_CloseObject(hContext, hIdentKey);
		Tspi_Context_CloseObject(hContext, hKey);
		exit(result);
	}

	pValidationData.DataLength = 20;
	memcpy( &pValidationData.ExternalData, &data, 20);

		//Call Key Certify Key
	result = Tspi_Key_CertifyKey(NonMigratableSigningKey, -1, 
				&pValidationData);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_HANDLE){
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, NonMigratableSigningKey);
			Tspi_Context_CloseObject(hContext, hIdentKey);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			exit(1);
		}
		else{
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, NonMigratableSigningKey);
			Tspi_Context_CloseObject(hContext, hIdentKey);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			exit(1);
		}
	}
	else{
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_CloseObject(hContext, NonMigratableSigningKey);
		Tspi_Context_CloseObject(hContext, hIdentKey);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
