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
 *	Tspi_Key_CreateKeyWithPcrs02.c
 *
 * DESCRIPTION
 *	This test will create 2 keys one with the PCRs ignored on read flag, the
 *	other without it, each bound to 1 PCR (15). Once created, Tspi_TPM_GetPubKey
 *	will be used to test whether the TPM is checking the ignore on read flag.
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
 *	Test:	Call Tspi_Key_CreateKey to create 2 keys, one 1.1 key and one 1.2 key, each bound
 *		  to the same PCR value.
 *		Call Tspi_Key_GetPubKey on each key while the PCR value is in the same state as
 *		  at key creation time, expecting success.
 *		Corrupt the PCR that the keys are bound to.
 *		Call Tspi_Key_GetPubKey on each key expecting success on the 1.2 key and
 *		  TPM_E_WRONGPCRVAL from the 1.1 key.
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
 *	Kent Yoder, shpedoikal@gmail.com, 10/10/2011
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

main_v1_1(void)
{
	char		*nameOfFunction = "Tspi_Key_CreateKeyWithPcrs02";
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_FLAG	initFlags;
	TSS_HKEY	hKey, hKey11;
	TSS_HKEY	hSRK;
	TSS_HPCRS	hPcrs, hPcrs11;
	TSS_RESULT	result;
	TSS_HPOLICY	srkUsagePolicy, keyUsagePolicy;
	BYTE		*pcrValue, *pub_blob;
	UINT32		pcrLen, pub_len;
	BYTE		pcrData[] = "09876543210987654321";
	initFlags	= TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048  |
			TSS_KEY_VOLATILE | TSS_KEY_NOT_MIGRATABLE;

	print_begin_test(nameOfFunction);


	result = connect_load_all(&hContext, &hSRK, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("connect_load_all", result);
		exit(result);
	}

		//Create Object with PCRSIGNOREDONREAD set
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
				initFlags | TSS_KEY_STRUCT_KEY12, &hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Create Object without PCRSIGNOREDONREAD set
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
				initFlags, &hKey11);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Create PCRs Object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS,
					   TSS_PCRS_STRUCT_INFO_LONG, &hPcrs);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS,
					   0, &hPcrs11);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Get PCR vals from TPM
	result = Tspi_TPM_PcrRead(hTPM, 15, &pcrLen, &pcrValue);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_PcrRead", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_PcrComposite_SetPcrLocality( hPcrs, TPM_LOC_ZERO );
	if ( result != TSS_SUCCESS ) {
		print_error( "Tspi_PcrComposite_SetPcrLocality", result );
		Tspi_Context_Close( hContext );
		exit( result );
	}


		//Set PCR vals in the objects
	result = Tspi_PcrComposite_SetPcrValue(hPcrs, 15, pcrLen, pcrValue);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_PcrComposite_SetPcrValue(hPcrs11, 15, pcrLen, pcrValue);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	Tspi_Context_FreeMemory(hContext, pcrValue);

	// Create both keys
	result = Tspi_Key_CreateKey(hKey, hSRK, hPcrs);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_CreateKey(hKey11, hSRK, hPcrs11);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_LoadKey(hKey, hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_LoadKey ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_LoadKey(hKey11, hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_LoadKey ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	// TEST 1: GetPubKey should succeed because PCRSIGNOREDONREAD is set for this 1.2 key
	result = Tspi_Key_GetPubKey(hKey, &pub_len, &pub_blob);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_GetPubKey ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	} else {
		print_success("Tspi_Key_GetPubKey", result);
	}

	result = Tspi_Context_FreeMemory(hContext, pub_blob);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_FreeMemory", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	// TEST 2: GetPubKey should succeed as long as PCR 15 hasn't changed for this 1.1 key, which
	// knows nothing about PCRSIGNOREDONREAD
	result = Tspi_Key_GetPubKey(hKey11, &pub_len, &pub_blob);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_GetPubKey ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	} else {
		print_success("Tspi_Key_GetPubKey", result);
	}

	result = Tspi_Context_FreeMemory(hContext, pub_blob);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_FreeMemory", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	// now, change a PCR value that the key cares about
	result = Tspi_TPM_PcrExtend(hTPM, 15, 20, pcrData, NULL,
				    &pcrLen, &pcrValue);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_PcrExtend ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	// TEST 3: GetPubKey should still succeed, since this key has PCRSIGNOREDONREAD
	result = Tspi_Key_GetPubKey(hKey, &pub_len, &pub_blob);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_GetPubKey", result);
		print_verifyerr("Tspi_Key_GetPubKey return code", TPM_E_WRONGPCRVAL, result);
		Tspi_Context_Close(hContext);
		exit(result);
	} else {
		print_success("Tspi_Key_GetPubKey", result);
	}

	result = Tspi_Context_FreeMemory(hContext, pub_blob);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_FreeMemory", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	// TEST 4: GetPubKey should fail with TPM_E_WRONGPCRVAL now that PCR 15 is hosed
	result = Tspi_Key_GetPubKey(hKey11, &pub_len, &pub_blob);
	if (result != TPM_E_WRONGPCRVAL) {
		print_error("Tspi_Key_GetPubKey", result);
		print_verifyerr("Tspi_Key_GetPubKey return code", TPM_E_WRONGPCRVAL, result);
		Tspi_Context_Close(hContext);
		exit(result);
	} else {
		print_success("Tspi_Key_GetPubKey", result);
	}

	print_success(nameOfFunction, result);
	print_end_test(nameOfFunction);
	Tspi_Context_CloseObject(hContext, hKey);
	Tspi_Context_Close(hContext);
	exit(0);
}
