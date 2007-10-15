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
 *	Tspi_Data_Unseal01.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_Data_Unseal
 *		returns TSS_SUCCESS.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Create Key Object
 *		Create Enc Data
 *		Load Key By UUID
 *		Create PCR Composite
 *		Set PCR Value
 *		Seal Data
 *
 *	Test:
 *		Call Data_Unseal then if it does not succeed
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
 *      Megan Schneider, mschnei@us.ibm.com, 6/04.
 *      Kent Yoder, shpedoikal@gmail.com, 09/16/04
 *        Added code for srk auth, encdata auth, key creation
 *	EJR, ejratl@gmail.com, 8/10/2006, 1.2
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
	if (version == TESTSUITE_TEST_TSS_1_2)
		main_v1_2(version);
	else if (version == TESTSUITE_TEST_TSS_1_1)
		print_NA();
	else
		print_wrongVersion();
}

#define DATA_SIZE	((2048/8)-40-2-65)

int
main_v1_2(char version)
{
	char *function = "Tspi_Data_Unseal-trans01";
	TSS_HCONTEXT hContext;
	TSS_HKEY hSRK, hKey, hSigningKey, hWrappingKey;
	TSS_HTPM hTPM;
	TSS_HPOLICY hKeyPolicy, hEncUsagePolicy, hSRKPolicy;
	BYTE rgbDataToSeal[DATA_SIZE];
	BYTE *rgbPcrValue;
	UINT32 ulPcrLen;
	TSS_HENCDATA hEncData;
	BYTE *prgbDataToUnseal;
	TSS_HPCRS hPcrComposite;
	UINT32 BlobLength;
	UINT32 ulDataLength = DATA_SIZE, ulNewDataLength;
	TSS_UUID uuid;
	TSS_RESULT result;
	TSS_FLAG initFlags = TSS_KEY_TYPE_STORAGE | TSS_KEY_SIZE_2048 |
	    TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION |
	    TSS_KEY_NOT_MIGRATABLE;

	print_begin_test(function);

	memset(rgbDataToSeal, 0x5d, DATA_SIZE);

	result = connect_load_all(&hContext, &hSRK, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		exit(result);
	}

	result = Testsuite_Transport_Init(hContext, hSRK, hTPM, TRUE, FALSE, &hWrappingKey,
					  &hSigningKey);
	if (result != TSS_SUCCESS) {
		print_error("Testsuite_Transport_Init", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	// create hKey
	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   initFlags, &hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject (hKey)", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_ENCDATA,
					   TSS_ENCDATA_SEAL, &hEncData);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject (hEncData)",
			    result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	// get the use policy for the encrypted data to set its secret
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE,
					   &hEncUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Policy_SetSecret(hEncUsagePolicy, TESTSUITE_ENCDATA_SECRET_MODE,
				       TESTSUITE_ENCDATA_SECRET_LEN, TESTSUITE_ENCDATA_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret (hEncUsagePolicy)", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	// Assign the use policy to the object
	result = Tspi_Policy_AssignToObject(hEncUsagePolicy, hEncData);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_AssignToObject", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	// set the new key's authdata
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE,
					   &hKeyPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result =
	    Tspi_Policy_SetSecret(hKeyPolicy, TESTSUITE_KEY_SECRET_MODE, TESTSUITE_KEY_SECRET_LEN,
				  TESTSUITE_KEY_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret (hKeyPolicy)", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	// Assign the use policy to the object
	result = Tspi_Policy_AssignToObject(hKeyPolicy, hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_AssignToObject", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	// create the key
	result = Tspi_Key_CreateKey(hKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey (hKey)", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_LoadKey(hKey, hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_LoadKey (hKey)", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS,
					   0, &hPcrComposite);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject (hPcrComposite)",
			    result);
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
#define PCR_NUM	5

	result = Tspi_TPM_PcrRead(hTPM, PCR_NUM, &ulPcrLen, &rgbPcrValue);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_PcrRead", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result =
	    Tspi_PcrComposite_SetPcrValue(hPcrComposite, PCR_NUM, ulPcrLen,
					  rgbPcrValue);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_PcrComposite_SetPcrValue", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	// Data Seal
	result =
	    Tspi_Data_Seal(hEncData, hKey, ulDataLength, rgbDataToSeal,
			   hPcrComposite);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Data_Seal", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result =
	    Tspi_Data_Unseal(hEncData, hKey, &ulNewDataLength,
			     &prgbDataToUnseal);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Data_Unseal", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Testsuite_Transport_Final(hContext, hSigningKey);
	if (result != TSS_SUCCESS) {
		if (!(checkNonAPI(result))) {
			print_error(function, result);
		} else {
			print_error_nonapi(function, result);
		}
	} else {
		if (ulDataLength != ulNewDataLength) {
			printf
			    ("ERROR length of returned data doesn't match!\n");
			print_end_test(function);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_Close(hContext);
			exit(result);
		} else
		    if (memcmp
			(prgbDataToUnseal, rgbDataToSeal, ulDataLength)) {
			printf
			    ("ERROR data returned from unseal doesn't match!\n");
			print_end_test(function);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_Close(hContext);
			exit(result);
		}

		result =
		    Tspi_Context_FreeMemory(hContext, prgbDataToUnseal);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Context_FreeMemory ", result);
			print_error_exit(function, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}
		print_success(function, result);
	}

	print_end_test(function);
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_Close(hContext);
	exit(result);
}
