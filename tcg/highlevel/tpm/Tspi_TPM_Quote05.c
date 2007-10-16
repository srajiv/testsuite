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
 *	Tspi_TPM_Quote05.c
 *
 * DESCRIPTION
 *		This testcase will quote using a signing key on several PCR
 *		indices, then check the indices against the real TPM PCR
 *		values once quote returns.  This is intended to test whether
 *		the TSS is setting the correct PCR values int he PCR composite
 *		object after quote returns.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Create Object and Key for hKey
 *		Get TPM Object
 *		Load Key By UUID for SRK
 *		Get Policy Object for srkUsagePolicy, TPM
 *		Set Secret for srkUsagePolicy, TPM
 *		Create object for the hIdentKey
 *		Get Policy Object (key)
 *		Set Secret (key)
 *		Create hIdentKey
 *		Load Key
 *		Create PcrComposite
 *		SelectPcrIndex
 *		Get Random
 *
 *	Test:	Call Quote. If this is unsuccessful check for
 *		type of error, and make sure it returns the proper return code
 *
 *	Cleanup:
 *		Free memory associated with the context
 *		Close the hIdentKey Object
 *		Close the hKey Object
 *		Close the hPcrComposite Object
 *		Close the context
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
 *	Kent Yoder <kyoder@users.sf.net>, removed unneeded code.
 *
 * RESTRICTIONS
 *	None.
 */

#include "common.h"


int main(int argc, char **argv)
{
	char version;

	version = parseArgs( argc, argv );
	if (version)
		main_v1_1();
	else
		print_wrongVersion();
}

main_v1_1(void){

	char		*nameOfFunction = "Tspi_TPM_Quote05";
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_HTPM	hTPM;
	TSS_HKEY	hSRK;
	TSS_HKEY	hIdentKey;
	TSS_HPCRS	hPcrComposite;
	TSS_FLAG	initFlags;
	TSS_HPOLICY	srkUsagePolicy;
	BYTE		*pcrValue1, *pcrValue2;
	UINT32		pcrSize1, pcrSize2;

	print_begin_test(nameOfFunction);

		//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Connect Context
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get TPM Object
	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetTpmObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext,
			TSS_PS_TYPE_SYSTEM,
			SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
#ifndef TESTSUITE_NOAUTH_SRK
		//Get Policy Object
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret
	result = Tspi_Policy_SetSecret(srkUsagePolicy, TESTSUITE_SRK_SECRET_MODE,
					TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
#endif
		//Create object for the hIdentKey
	result = Tspi_Context_CreateObject(hContext,
			TSS_OBJECT_TYPE_RSAKEY,
			TSS_KEY_SIZE_2048 |TSS_KEY_TYPE_SIGNING, &hIdentKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Create hIdentKey
	result = Tspi_Key_CreateKey(hIdentKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		Tspi_Context_CloseObject(hContext, hIdentKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Key_LoadKey(hIdentKey, hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_LoadKey", result);
		Tspi_Context_CloseObject(hContext, hIdentKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Create object for the hPcrComposite Key
	result = Tspi_Context_CreateObject(hContext,
			TSS_OBJECT_TYPE_PCRS, 0,
			&hPcrComposite);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_CloseObject(hContext, hIdentKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//SelectPcrIndex
	result = Tspi_PcrComposite_SelectPcrIndex(hPcrComposite, 1);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_PcrComposite_SelectPcrIndex", result);
		Tspi_Context_CloseObject(hContext, hIdentKey);
		Tspi_Context_CloseObject(hContext, hPcrComposite);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_PcrComposite_SelectPcrIndex(hPcrComposite, 8);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_PcrComposite_SelectPcrIndex", result);
		Tspi_Context_CloseObject(hContext, hIdentKey);
		Tspi_Context_CloseObject(hContext, hPcrComposite);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_PcrComposite_SelectPcrIndex(hPcrComposite, 15);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_PcrComposite_SelectPcrIndex", result);
		Tspi_Context_CloseObject(hContext, hIdentKey);
		Tspi_Context_CloseObject(hContext, hPcrComposite);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Call TPM Quote
	result = Tspi_TPM_Quote(hTPM, hIdentKey, hPcrComposite, NULL);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_Quote", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	Tspi_Context_CloseObject(hContext, hIdentKey);

	result = Tspi_PcrComposite_GetPcrValue(hPcrComposite, 1, &pcrSize1,
					       &pcrValue1);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_PcrComposite_GetPcrValue", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_TPM_PcrRead(hTPM, 1, &pcrSize2, &pcrValue2);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_PcrRead", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	if (pcrSize1 == pcrSize2 && !memcmp(pcrValue1, pcrValue2, pcrSize1))
		print_success(nameOfFunction, result);
	else {
		fprintf(stderr, "Verifying PCR 1 failed.\n");
		fprintf(stderr, "pcrSize1: %u, pcrSize2: %u\n", pcrSize1, pcrSize2);
		fprintf(stderr, "PCR#1 from composite:\n");
		print_hex(pcrValue1, pcrSize1);
		fprintf(stderr, "PCR#1 from PcrRead:\n");
		print_hex(pcrValue2, pcrSize2);
		Tspi_Context_Close(hContext);
		exit(1);
	}

	result = Tspi_PcrComposite_GetPcrValue(hPcrComposite, 8, &pcrSize1,
					       &pcrValue1);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_PcrComposite_GetPcrValue", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_TPM_PcrRead(hTPM, 8, &pcrSize2, &pcrValue2);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_PcrRead", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	if (pcrSize1 == pcrSize2 && !memcmp(pcrValue1, pcrValue2, pcrSize1))
		print_success(nameOfFunction, result);
	else {
		fprintf(stderr, "Verifying PCR 8 failed.\n");
		fprintf(stderr, "pcrSize1: %u, pcrSize2: %u\n", pcrSize1, pcrSize2);
		fprintf(stderr, "PCR#8 from composite:\n");
		print_hex(pcrValue1, pcrSize1);
		fprintf(stderr, "PCR#8 from PcrRead:\n");
		print_hex(pcrValue2, pcrSize2);
		Tspi_Context_Close(hContext);
		exit(1);
	}

	result = Tspi_PcrComposite_GetPcrValue(hPcrComposite, 15, &pcrSize1,
					       &pcrValue1);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_PcrComposite_GetPcrValue", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_TPM_PcrRead(hTPM, 15, &pcrSize2, &pcrValue2);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_PcrRead", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	if (pcrSize1 == pcrSize2 && !memcmp(pcrValue1, pcrValue2, pcrSize1))
		print_success(nameOfFunction, result);
	else {
		fprintf(stderr, "Verifying PCR 15 failed.\n");
		fprintf(stderr, "pcrSize1: %u, pcrSize2: %u\n", pcrSize1, pcrSize2);
		fprintf(stderr, "PCR#15 from composite:\n");
		print_hex(pcrValue1, pcrSize1);
		fprintf(stderr, "PCR#15 from PcrRead:\n");
		print_hex(pcrValue2, pcrSize2);
		Tspi_Context_Close(hContext);
		exit(1);
	}

	print_success(nameOfFunction, result);
	print_end_test(nameOfFunction);
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_Close(hContext);
	exit(0);
}
