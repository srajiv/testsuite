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
 *	Tspi_Hash_TickStampBlob01.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_Hash_TickStampBlob succeeds.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Load SRK
 *		Get Policy Object
 *		Set Secret
 *		Create Signing Key Object
 *		Create Signing Key
 *		Load Key
 *		Create Hash Object
 *		Set Hash Value
 *
 *	Test:
 *		Call Hash_Sign then if it does not succeed
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
 *      This test case is currently only implemented for v1.1 and 1.2
 *
 * HISTORY
 *	Kent Yoder <kyoder@users.sf.net> 05/07
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include "common.h"


int main(int argc, char **argv)
{
	char version;

	version = parseArgs(argc, argv);
	if (version)
		main_v1_1();
	else
		print_wrongVersion();
}

int main_v1_1(void)
{
	char *function = "Tspi_Hash_TickStampBlob01";
	TSS_HCONTEXT hContext;
	TSS_HKEY hSRK, hMSigningKey;
	TSS_HHASH hHash;
	TSS_HTPM hTPM;
	TSS_RESULT result;
	TSS_HPOLICY srkUsagePolicy;
	TSS_VALIDATION validationData;
	BYTE *nonce;

	print_begin_test(function);

	// Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create", result);
		print_error_exit(function, err_string(result));
		exit(result);
	}
	// Connect to Context
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetTpmObject", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
					    SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID (hSRK)", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
#ifndef TESTSUITE_NOAUTH_SRK
	//Get Policy Object
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE,
				      &srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Set Secret
	result = Tspi_Policy_SetSecret(srkUsagePolicy, TESTSUITE_SRK_SECRET_MODE,
				       TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
#endif
	//Create Signing Key
	result =
	    Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
				      TSS_KEY_SIZE_2048 |
				      TSS_KEY_TYPE_SIGNING |
				      TSS_KEY_NO_AUTHORIZATION,
				      &hMSigningKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject (signing key)",
			    result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_CreateKey(hMSigningKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey (signing key)", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_LoadKey(hMSigningKey, hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKey (hMSigningKey)", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	// create hash
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH,
					   TSS_HASH_SHA1, &hHash);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject (hash)", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Hash_SetHashValue(hHash, 20, "Je pense, danc je s");
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Hash_SetHashValue", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_TPM_GetRandom(hTPM, 20, &nonce);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_GetRandom", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	validationData.rgbExternalData = nonce;
	validationData.ulExternalDataLength = 20;

	result = Tspi_Hash_TickStampBlob(hHash, hMSigningKey, &validationData);
	if (result != TSS_SUCCESS) {
		if (!(checkNonAPI(result))) {
			print_error(function, result);
		} else {
			print_error_nonapi(function, result);
		}
	} else {
		print_success(function, result);
	}

	print_end_test(function);
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_Close(hContext);
	exit(result);
}
