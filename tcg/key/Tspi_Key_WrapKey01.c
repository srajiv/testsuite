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
 *	Tspi_Key_WrapKey01.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_Key_WrapKey.
 *	The purpose of this test case is to get TSS_SUCCESS to be
 *		returned. This is done by following the algorithm
 *		described below.
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
 *	Author:	Kathy Robertson
 *	Date:	June 2004
 *	Email:	klrobert@us.ibm.com
 *
 * RESTRICTIONS
 *	None.
 */

#include <trousers/tss.h>
#include "../common/common.h"

#include <openssl/rsa.h>



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

	char		*nameOfFunction = "Tspi_Key_WrapKey01";
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_FLAG	initFlags;
	TSS_HKEY	hKey;
	TSS_HKEY	hSRK, hParentKey;
	TSS_RESULT	result;
	TSS_UUID	uuid;
	TSS_HPOLICY	srkUsagePolicy, keyUsagePolicy, keyMigPolicy;
	initFlags	= TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048  |
			TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
			TSS_KEY_NOT_MIGRATABLE;
	RSA		*rsa = NULL;
	unsigned char	n[2048], p[2048];
	int		size_n, size_p;

	print_begin_test(nameOfFunction);

		//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect ", result);
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
		//Create Object
	result = Tspi_Context_CreateObject(hContext, 
					TSS_OBJECT_TYPE_RSAKEY,
					initFlags, &hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Load Parent Key By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext, 
				TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get Policy Object
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, 
					&srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret
	result = Tspi_Policy_SetSecret(srkUsagePolicy, 
					TSS_SECRET_MODE_PLAIN,
					0, NULL);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// generate a software key to wrap
	if ((rsa = RSA_generate_key(2048, 65537, NULL, NULL)) == NULL) {
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(1);
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

		// set the public key data in the TSS object
	result = Tspi_SetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
			TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, size_n, n);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_SetAttribData ", result);
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

		//Create Object
	result = Tspi_Context_CreateObject(hContext,
					TSS_OBJECT_TYPE_RSAKEY,
					TSS_KEY_TYPE_STORAGE |
					TSS_KEY_SIZE_2048,
					&hParentKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Create Parent Key
	result = Tspi_Key_CreateKey(hParentKey, hSRK, NULL_HPCRS);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Wrap Key
	result = Tspi_Key_WrapKey(hKey, hParentKey, NULL_HPCRS);
	if (result != TSS_SUCCESS){
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			RSA_free(rsa);
			exit(1);
		}
		else{
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			RSA_free(rsa);
			exit(1);
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
