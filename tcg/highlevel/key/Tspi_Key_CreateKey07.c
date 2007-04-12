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
 *	Tspi_Key_CreateKey07.c
 *
 * DESCRIPTION
 *	This test creates a key, then checks that attributes of the key
 *	can no longer be changed.
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
 *		This test case is currently only implemented for 1.1 and 1.2
 *
 * HISTORY
 *	Kent Yoder, kyoder@users.sf.net, 4/2007
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
	char *nameOfFunction = "Tspi_Key_CreateKey07";
	TSS_HCONTEXT hContext;
	TSS_FLAG initFlags;
	TSS_HKEY hKey;
	TSS_HKEY hSRK;
	TSS_RESULT result;
	TSS_HPOLICY srkUsagePolicy;
	BYTE *blob, *pubblob, *privblob;
	UINT32 blob_size, pubblob_size, privblob_size, trash;

	initFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_512 |
	    TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
	    TSS_KEY_NOT_MIGRATABLE;

	print_begin_test(nameOfFunction);

	//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create", result);
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
	//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext,
					    TSS_PS_TYPE_SYSTEM, SRK_UUID,
					    &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
#ifndef TESTSUITE_NOAUTH_SRK
	//Get Policy Object
	result =
	    Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Set Secret
	result =
	    Tspi_Policy_SetSecret(srkUsagePolicy,
				  TESTSUITE_SRK_SECRET_MODE,
				  TESTSUITE_SRK_SECRET_LEN,
				  TESTSUITE_SRK_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
#endif

	//Create Object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
					   initFlags, &hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	//Create Key
	result = Tspi_Key_CreateKey(hKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB,
				    &blob_size, &blob);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetAttribData", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
				    TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
				    &pubblob_size, &pubblob);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetAttribData", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
				    TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY,
				    &privblob_size, &privblob);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetAttribData", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}


	/* TEST 1 */
	result = Tspi_SetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
				    TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
				    pubblob_size, pubblob);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_OBJ_ACCESS) {
		print_error("Tspi_SetAttribData", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	} else
		print_success("TEST 1", result);

	/* TEST 2 */
	result = Tspi_SetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
				    TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY,
				    privblob_size, privblob);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_OBJ_ACCESS) {
		print_error("Tspi_SetAttribData", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	} else
		print_success("TEST 2", result);

	/* TEST 3 */
	result = Tspi_SetAttribData(hKey, TSS_TSPATTRIB_RSAKEY_INFO,
				    TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT,
				    blob_size, blob);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_OBJ_ACCESS) {
		print_error("Tspi_SetAttribData", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	} else
		print_success("TEST 3", result);

	/* TEST 4 */
	result = Tspi_SetAttribData(hKey, TSS_TSPATTRIB_RSAKEY_INFO,
				    TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
				    blob_size, blob);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_OBJ_ACCESS) {
		print_error("Tspi_SetAttribData", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	} else
		print_success("TEST 4", result);

	/* TEST 5 */
	result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
				    TSS_TSPATTRIB_KEYINFO_USAGE, trash);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_OBJ_ACCESS) {
		print_error("Tspi_SetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	} else
		print_success("TEST 5", result);

	/* TEST 6 */
	trash = TRUE;
	result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
				    TSS_TSPATTRIB_KEYINFO_MIGRATABLE, trash);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_OBJ_ACCESS) {
		print_error("Tspi_SetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	} else
		print_success("TEST 6", result);

	/* TEST 7 */
	result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
				    TSS_TSPATTRIB_KEYINFO_REDIRECTED, trash);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_OBJ_ACCESS) {
		print_error("Tspi_SetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	} else
		print_success("TEST 7", result);

	/* TEST 8 */
	result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
				    TSS_TSPATTRIB_KEYINFO_VOLATILE, trash);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_OBJ_ACCESS) {
		print_error("Tspi_SetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	} else
		print_success("TEST 8", result);

	/* TEST 9 */
	result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
				    TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE, trash);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_OBJ_ACCESS) {
		print_error("Tspi_SetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	} else
		print_success("TEST 9", result);

	/* TEST 10 */
	result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
				    TSS_TSPATTRIB_KEYINFO_ALGORITHM, trash);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_OBJ_ACCESS) {
		print_error("Tspi_SetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	} else
		print_success("TEST 10", result);

	/* TEST 11 */
	trash = TSS_ES_NONE;
	result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
				    TSS_TSPATTRIB_KEYINFO_ENCSCHEME, trash);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_OBJ_ACCESS) {
		print_error("Tspi_SetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	} else
		print_success("TEST 11", result);

	/* TEST 12 */
	trash = TSS_SS_NONE;
	result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
				    TSS_TSPATTRIB_KEYINFO_SIGSCHEME, trash);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_OBJ_ACCESS) {
		print_error("Tspi_SetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	} else
		print_success("TEST 12", result);

	/* TEST 13 */
	result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
				    TSS_TSPATTRIB_KEYINFO_SIZE, trash);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_OBJ_ACCESS) {
		print_error("Tspi_SetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	} else
		print_success("TEST 13", result);

	/* TEST 14 */
	result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
				    TSS_TSPATTRIB_KEYINFO_KEYFLAGS, trash);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_OBJ_ACCESS) {
		print_error("Tspi_SetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	} else
		print_success("TEST 14", result);

	/* TEST 15 */
	trash = TRUE;
	result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
				    TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, trash);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_OBJ_ACCESS) {
		print_error("Tspi_SetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	} else
		print_success("TEST 15", result);

	/* TEST 16 */
	result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_RSAKEY_INFO,
				    TSS_TSPATTRIB_KEYINFO_RSA_PRIMES, trash);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_OBJ_ACCESS) {
		print_error("Tspi_SetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	} else
		print_success("TEST 16", result);

	print_success(nameOfFunction, TSS_SUCCESS);
	print_end_test(nameOfFunction);
	Tspi_Context_Close(hContext);
	exit(0);
}
