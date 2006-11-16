/*
 *
 *   Copyright (C) International Business Machines  Corp., 2005
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
 *	Tspi_TPM_CollateIdentityRequest01.c
 *
 * DESCRIPTION
 *	This test will attempt to create an identity key by calling
 *	Tspi_TPM_CollateIdentityRequest.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context, load the SRK and get a TPM handle
 *		Generate an openssl RSA key to represent the CA's key
 *		Create the identtiy key's object
 *
 *	Test:	Call Tspi_TPM_CollateIdentityRequest
 *		Make sure that it returns the proper return codes
 *
 *	Cleanup:
 *		Free memory associated with the context 
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1
 *
 * HISTORY
 *	Kent Yoder, kyoder@users.sf.net
 *
 * RESTRICTIONS
 *	None.
 */

#include "common.h"

#include <openssl/rsa.h>

#define CA_KEY_SIZE_BITS 2048


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

	char		*nameOfFunction = "Tspi_TPM_CollateIdentityRequest01";
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_FLAG	initFlags;
	TSS_HKEY	hSRK, hIdentKey, hCAKey;
	TSS_HPOLICY	hTPMPolicy;
	TSS_RESULT	result;
	RSA		*rsa = NULL;
	unsigned char	n[2048];//, p[2048];
	int		size_n;//, size_p;
	BYTE		*rgbIdentityLabelData = NULL, *rgbTCPAIdentityReq;
	BYTE		*labelString = "My Identity Label";
	UINT32		labelLen = strlen(labelString) + 1;
	UINT32		ulTCPAIdentityReqLength;

	initFlags	= TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048  |
			TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
			TSS_KEY_NOT_MIGRATABLE;

	print_begin_test(nameOfFunction);

		//Create Context
	result = connect_load_all(&hContext, &hSRK, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("connect_load_all", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}

		//Insert the owner auth into the TPM's policy
	result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTPMPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}

	result = Tspi_Policy_SetSecret(hTPMPolicy, TESTSUITE_OWNER_SECRET_MODE,
				       TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}

		//Create Identity Key Object
	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   initFlags, &hIdentKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Create CA Key Object
	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_2048,
					   &hCAKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// generate a software key to represent the CA's key
	if ((rsa = RSA_generate_key(CA_KEY_SIZE_BITS, 65537, NULL, NULL)) == NULL) {
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// get the pub CA key
	if ((size_n = BN_bn2bin(rsa->n, n)) <= 0) {
		fprintf(stderr, "BN_bn2bin failed\n");
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
                exit(254);
        }

		// set the CA's public key data in the TSS object
	result = set_public_modulus(hContext, hCAKey, size_n, n);
	if (result != TSS_SUCCESS) {
		print_error("set_public_modulus", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}

		// set the CA key's algorithm
	result = Tspi_SetAttribUint32(hCAKey, TSS_TSPATTRIB_KEY_INFO,
				      TSS_TSPATTRIB_KEYINFO_ALGORITHM,
				      TSS_ALG_RSA);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_SetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}

		// set the CA key's number of primes
	result = Tspi_SetAttribUint32(hCAKey, TSS_TSPATTRIB_RSAKEY_INFO,
				      TSS_TSPATTRIB_KEYINFO_RSA_PRIMES,
				      2);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_SetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}

	rgbIdentityLabelData = TestSuite_Native_To_UNICODE(labelString, &labelLen);
	if (rgbIdentityLabelData == NULL) {
		fprintf(stderr, "TestSuite_Native_To_UNICODE failed\n");
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
                exit(result);
	}

	result = Tspi_TPM_CollateIdentityRequest(hTPM, hSRK, hCAKey, labelLen,
						 rgbIdentityLabelData,
						 hIdentKey, TSS_ALG_AES,
						 &ulTCPAIdentityReqLength,
						 &rgbTCPAIdentityReq);
	if (result != TSS_SUCCESS){
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			RSA_free(rsa);
			exit(result);
		}
		else{
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			RSA_free(rsa);
			exit(result);
		}
	}
	else{
		result = Tspi_Context_FreeMemory(hContext, rgbTCPAIdentityReq);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Context_FreeMemory ", result);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		RSA_free(rsa);
		exit(0);
	}
}
