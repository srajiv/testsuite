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
 *	Tspi_Key_CreateKeyWithPcrs.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_Key_CreateKey.
 *	The purpose of this test case is to get TSS_SUCCESS to be
 *		returned. This is easily accomplished by following
 *		the algorithm described below.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Create Object
 *		Load SRK By UUID
 *		Get Policy Object
 *		Set Secret
 *
 *	Test:	Call CreateKey. If it is not a success
 *		Make sure that it returns the proper return codes
 *
 *	Cleanup:
 *		Close hKey object
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
 *	Kent Yoder, shpedoikal@gmail.com, 10/11/2004
 *	  Removed unneeded code
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

	char		*nameOfFunction = "Tspi_Key_CreateKeyWithPcrs";
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_FLAG	initFlags;
	TSS_HKEY	hKey;
	TSS_HKEY	hSRK;
	TSS_HPCRS	hPcrs;
	TSS_RESULT	result;
	TSS_HPOLICY	srkUsagePolicy, keyUsagePolicy;
	BYTE		*pcrValue;
	UINT32		pcrLen;
	BYTE		pcrData[] = "09876543210987654321";
	initFlags	= TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048  |
			TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION |
			TSS_KEY_NOT_MIGRATABLE;

	print_begin_test(nameOfFunction);


	result = connect_load_all(&hContext, &hSRK, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("connect_load_all", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}

		//Create Object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
				initFlags, &hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get Policy Object
	result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE, &keyUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret
	result = Tspi_Policy_SetSecret(keyUsagePolicy, TESTSUITE_KEY_SECRET_MODE,
				TESTSUITE_KEY_SECRET_LEN, TESTSUITE_KEY_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Create PCRs Object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS,
					   0, &hPcrs);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get PCR vals from TPM
	result = Tspi_TPM_PcrRead(hTPM, 1, &pcrLen, &pcrValue);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_PcrRead", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set PCR vals in the object
	result = Tspi_PcrComposite_SetPcrValue(hPcrs, 1, pcrLen, pcrValue);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	Tspi_Context_FreeMemory(hContext, pcrValue);

		//Get PCR vals from TPM
	result = Tspi_TPM_PcrRead(hTPM, 15, &pcrLen, &pcrValue);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_PcrRead", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set PCR vals in the object
	result = Tspi_PcrComposite_SetPcrValue(hPcrs, 15, pcrLen, pcrValue);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	Tspi_Context_FreeMemory(hContext, pcrValue);

		//Create Key
	result = Tspi_Key_CreateKey(hKey, hSRK, hPcrs);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	/* if the key loads, the key creation is successful */
	result = Tspi_Key_LoadKey(hKey, hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_LoadKey ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	/* now, encrypt and decrypt some data to see if the key "works" */
	result = bind_and_unbind(hContext, hKey);
	if (result != TSS_SUCCESS) {
		print_error("bind_and_unbind ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	/* now, change a PCR value that the key is set to */
	result = Tspi_TPM_PcrExtend(hTPM, 15, 20, pcrData, NULL,
				    &pcrLen, &pcrValue);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_PcrExtend ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	/* now, encrypt and decrypt some data, which should fail, since
	 * the PCR changed */
	result = bind_and_unbind(hContext, hKey);
	if (result != TCPA_E_WRONGPCRVAL){
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			exit(result);
		}
		else{
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}
	else{
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
