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
 *	Tspi_Key_WrapKeyToPcr.c
 *
 * DESCRIPTION
 *	This test will wrap a software key bound to 2 PCRS (1 and 15), bind and
 *	unbind some data to verify that that works, then trash one of the
 *	PCRs and try to sign/verify some data, looking for TCPA_E_WRONGPCRVAL.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect
 *		Create an empty key Object
 *		Load the SRK By UUID
 *		Get Policy Object of SRK
 *		Set Secret of SRK's policy object
 *		Generate an openssl RSA key
 *		Set the public key of the enpty TSS key object to the value
 *		 of the openssl RSA key
 *		Set the private key of the enpty TSS key object to the value
 *		 of one of the openssl RSA key's primes
 *		Call wrap key using the SRK as the parent
 *
 *	Test:	Call WrapKey01. If it is not a success
 *		Make sure that it returns the proper return codes
 *
 *	Cleanup:
 *		Free memory associated with the context 
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
 *	Author:	Kent Yoder <kyoder@users.sf.net>
 *
 * RESTRICTIONS
 *	None.
 */

#include "common.h"

#include <openssl/rsa.h>


int main(int argc, char **argv)
{
	char version;

	version = parseArgs( argc, argv );
	if (version)
		main_v1_2(version);
	else
		print_wrongVersion();
}

main_v1_2(char version){

	char		*nameOfFunction = "Tspi_Key_WrapKeyToPcr";
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_FLAG	initFlags;
	TSS_HKEY	hKey, hSRK;
	TSS_HPCRS	hPcrs;
	TSS_RESULT	result;
	TSS_HPOLICY	srkUsagePolicy, hPolicy;
	RSA		*rsa = NULL;
	unsigned char	n[2048], p[2048];
	int		size_n, size_p;
	BYTE		pcrData[] = "09876543210987654321";
	BYTE		*pcrValue, *srkPub;
	UINT32		pcrLen, srkPubLen;

	print_begin_test(nameOfFunction);

	initFlags	= TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048  |
			TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
			TSS_KEY_MIGRATABLE;

		//Create Context
	result = connect_load_all(&hContext, &hSRK, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect ", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}

		// In a 1.2 TPM, we need to make sure the SRK can be read before continuing
	if (version == TESTSUITE_TEST_TSS_1_2) {
		result = set_srk_readable(hContext);
		if (result != TSS_SUCCESS) {
			print_error("set_srk_readable", result);
			print_error_exit(nameOfFunction, err_string(result));
			exit(result);
		}
	}

		// Get the SRK's pub key
	result = Tspi_Key_GetPubKey(hSRK, &srkPubLen, &srkPub);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_GetPubKey ", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
	Tspi_Context_FreeMemory(hContext, srkPub);

		//Create Key Object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Create policy Object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_MIGRATION,
					   &hPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Set the key's migration secret
	result = Tspi_Policy_SetSecret(hPolicy, TESTSUITE_KEY_SECRET_MODE, TESTSUITE_KEY_SECRET_LEN,
				       TESTSUITE_KEY_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Create PCRs Object
	result = Tspi_Policy_AssignToObject(hPolicy, hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_AssignToObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Create PCRs Object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS, 0, &hPcrs);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// generate a software key to wrap
	if ((rsa = RSA_generate_key(2048, 65537, NULL, NULL)) == NULL) {
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(-1);
	}

		// get the pub key and a prime
	if ((size_n = BN_bn2bin(rsa->n, n)) <= 0) {
		fprintf(stderr, "BN_bn2bin failed\n");
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
                exit(-1);
        }

        if ((size_p = BN_bn2bin(rsa->p, p)) <= 0) {
		fprintf(stderr, "BN_bn2bin failed\n");
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
                exit(-1);
        }

	result = set_public_modulus(hContext, hKey, size_n, n);
	if (result != TSS_SUCCESS) {
		print_error("set_public_modulus", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}

		// set the private key data in the TSS object
	result = Tspi_SetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
			TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY, size_p, p);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_SetAttribData ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
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

		//Wrap Key
	result = Tspi_Key_WrapKey(hKey, hSRK, hPcrs);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_WrapKey ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}

	/* if the key loads, the key creation is successful */
	result = Tspi_Key_LoadKey(hKey, hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_LoadKey ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}

	/* now, encrypt and decrypt some data to see if the key "works" */
	result = bind_and_unbind(hContext, hKey);
	if (result != TSS_SUCCESS) {
		print_error("bind_and_unbind 1", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}

	/* now, change a PCR value that the key is set to */
	result = Tspi_TPM_PcrExtend(hTPM, 15, 20, pcrData, NULL,
				    &pcrLen, &pcrValue);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_PcrExtend ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}

	/* now, encrypt and decrypt some data, which should fail, since
	 * the PCR changed */
	result = bind_and_unbind(hContext, hKey);
	if (TSS_ERROR_CODE(result) != TCPA_E_WRONGPCRVAL){
		if(!checkNonAPI(result)){
			print_error("bind_and_unbind 2", result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			RSA_free(rsa);
			exit(result);
		}
		else{
			print_error_nonapi("bind_and_unbind", result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			RSA_free(rsa);
			exit(result);
		}
	}
	else{
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(0);
	}
}
