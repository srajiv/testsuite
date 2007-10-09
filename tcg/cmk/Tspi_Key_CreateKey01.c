/*
 *
 *   Copyright (C) International Business Machines  Corp., 2007
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
 *	Tspi_Key_CreateKey01.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_Key_CreateKey for a CMK Key.
 *	The purpose of this test case is to get TSS_SUCCESS to be
 *		returned. This is easily accomplished by following
 *		the algorithm described below.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Load SRK By UUID
 *              Perform overall CMK setup
 *		Grant approval of MA's / MSA's
 *
 *	Test:	Call CreateKey. If it is not a success
 *		Make sure that it returns the proper return codes
 *
 *	Cleanup:
 *		Close context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.2
 *
 * HISTORY
 *      Tom Lendacky, toml@us.ibm.com, 8/07.
 *
 * RESTRICTIONS
 *	None.
 */

#include "common.h"


static char *nameOfFunction = "Tspi_Key_CreateKey01";


void
tc_create_object(TSS_HCONTEXT hContext, UINT32 type, UINT32 flags, TSS_HOBJECT *hObject)
{
	TSS_RESULT result;

	//Create Object
	result = Tspi_Context_CreateObject(hContext, type, flags, hObject);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
}

void
tc_create_policy(TSS_HCONTEXT hContext, UINT32 type, UINT32 flags, TSS_HOBJECT hObject)
{
	TSS_HPOLICY hPolicy;
	TSS_RESULT result;

	//Create Policy Object
	tc_create_object(hContext, type, flags, &hPolicy);

	//Set Policy Secret
	result = Tspi_Policy_SetSecret(hPolicy, TESTSUITE_KEY_SECRET_MODE,
			TESTSUITE_KEY_SECRET_LEN, TESTSUITE_KEY_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	//Assign Policy to Object (Key)
	result = Tspi_Policy_AssignToObject(hPolicy, hObject);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_AssignToObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
}

void
tc_create_key(TSS_HCONTEXT hContext, TSS_HKEY hKey, TSS_HKEY hParent, UINT32 flags)
{
	TSS_RESULT result;

	//Create Policy
	if (flags & TSS_KEY_AUTHORIZATION) {
		//Create Usage Policy Object
		tc_create_policy(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, hKey);

		if (flags & TSS_KEY_MIGRATABLE) {
			//Create Migration Policy Object
			tc_create_policy(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_MIGRATION, hKey);
		}
	}

	//Create Key
	result = Tspi_Key_CreateKey(hKey, hParent, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
}

void
tc_load_key(TSS_HCONTEXT hContext, TSS_HKEY hKey, TSS_HKEY hParent)
{
	TSS_RESULT result;

	result = Tspi_Key_LoadKey(hKey, hParent);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_LoadKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
}

void
tc_get_attribdata(TSS_HCONTEXT hContext, TSS_HOBJECT hObject, UINT32 flag, UINT32 subflag, UINT32 *blobSize, BYTE **blob)
{
	TSS_RESULT result;

	result = Tspi_GetAttribData(hObject, flag, subflag, blobSize, blob);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetAttribData", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
}

void
tc_set_attribdata(TSS_HCONTEXT hContext, TSS_HOBJECT hObject, UINT32 flag, UINT32 subflag, UINT32 blobSize, BYTE *blob)
{
	TSS_RESULT result;

	result = Tspi_SetAttribData(hObject, flag, subflag, blobSize, blob);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_SetAttribData", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
}


int main(int argc, char **argv)
{
	char version;

	version = parseArgs( argc, argv );
	if (version >= TESTSUITE_TEST_TSS_1_2)
		main_v1_2(version);
	else
		print_NA();
}

#define MA_KEY_COUNT	3
main_v1_2(char version)
{
	TSS_HCONTEXT hContext;
	TSS_HKEY hSRK;
	TSS_HTPM hTPM;
	TSS_HPOLICY hTpmUsagePolicy;
	TSS_FLAG initFlags;
	TSS_HKEY hSrcKey;
	TSS_HKEY hDestKey;
	TSS_HKEY hMaKey[MA_KEY_COUNT];
	TSS_HKEY hCmkKey;
	TSS_HMIGDATA hMigData;
	TSS_HHASH hHash;
	UINT32 blobSize;
	BYTE *blob;
	int i;
	TSS_RESULT result;


	print_begin_test(nameOfFunction);

	result = connect_load_all(&hContext, &hSRK, &hTPM);
	if ( result != TSS_SUCCESS )
	{
		print_error( "connect_load_all", result );
		exit(result);
	}

	//Get TPM Policy Object
	result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTpmUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	//Set Secret
	result = Tspi_Policy_SetSecret(hTpmUsagePolicy, TESTSUITE_OWNER_SECRET_MODE,
			TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	/*****  Create Overall Source Parent key *****/
	initFlags = TSS_KEY_STRUCT_KEY12 | TSS_KEY_TYPE_STORAGE | TSS_KEY_SIZE_2048 |
			TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION;
	tc_create_object(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hSrcKey);
	tc_create_key(hContext, hSrcKey, hSRK, initFlags);
	tc_load_key(hContext, hSrcKey, hSRK);

	/*****  Create Overall Destination Parent key *****/
	initFlags = TSS_KEY_STRUCT_KEY12 | TSS_KEY_TYPE_STORAGE | TSS_KEY_SIZE_2048 |
			TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION;
	tc_create_object(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hDestKey);
	tc_create_key(hContext, hDestKey, hSRK, initFlags);
	tc_load_key(hContext, hDestKey, hSRK);

	/*****  Create MAs and MSA list *****/
	//Create MigData Object
	tc_create_object(hContext, TSS_OBJECT_TYPE_MIGDATA, 0, &hMigData);

	for (i = 0; i < MA_KEY_COUNT; i++) {
		//Create Key Object
		initFlags = TSS_KEY_STRUCT_KEY12 | TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 |
				TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION;
		tc_create_object(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hMaKey[i]);
		tc_create_key(hContext, hMaKey[i], hSrcKey, initFlags);

		//Get PubKey Blob
		tc_get_attribdata(hContext, hMaKey[i], TSS_TSPATTRIB_KEY_BLOB,
			TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, &blobSize, &blob);

		//Add PubKey Blob to the MSA list
		tc_set_attribdata(hContext, hMigData, TSS_MIGATTRIB_MIGRATIONBLOB,
			TSS_MIGATTRIB_MIG_MSALIST_PUBKEY_BLOB, blobSize, blob);
	}

	//Grant Owner Approval of MAs
	result = Tspi_TPM_CMKApproveMA(hTPM, hMigData);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_CMKApproveMA", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	/*****  Create a CMK  ****/
	initFlags = TSS_KEY_STRUCT_KEY12 | TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 |
			TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION |
			TSS_KEY_MIGRATABLE | TSS_KEY_CERTIFIED_MIGRATABLE;
	tc_create_object(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hCmkKey);

	//Get and Assign MA/MSA information
	tc_get_attribdata(hContext, hMigData, TSS_MIGATTRIB_AUTHORITY_DATA,
		TSS_MIGATTRIB_AUTHORITY_DIGEST, &blobSize, &blob);
	tc_set_attribdata(hContext, hCmkKey, TSS_TSPATTRIB_KEY_CMKINFO,
		TSS_TSPATTRIB_KEYINFO_CMK_MA_DIGEST, blobSize, blob);
	tc_get_attribdata(hContext, hMigData, TSS_MIGATTRIB_AUTHORITY_DATA,
		TSS_MIGATTRIB_AUTHORITY_APPROVAL_HMAC, &blobSize, &blob);
	tc_set_attribdata(hContext, hCmkKey, TSS_TSPATTRIB_KEY_CMKINFO,
		TSS_TSPATTRIB_KEYINFO_CMK_MA_APPROVAL, blobSize, blob);

	//Don't use the internal routine, tc_create_key, so that we can examine
	//the return code in more detail
	//Create Policy
	if (initFlags & TSS_KEY_AUTHORIZATION) {
		//Create Usage Policy Object
		tc_create_policy(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, hCmkKey);

		if (initFlags & TSS_KEY_MIGRATABLE) {
			//Create Migration Policy Object
			tc_create_policy(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_MIGRATION, hCmkKey);
		}
	}

	//Create Key
	result = Tspi_Key_CreateKey(hCmkKey, hSrcKey, 0);
	if (result != TSS_SUCCESS) {
		if (!checkNonAPI(result)) {
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(result);
		} else {
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}

	print_success(nameOfFunction, result);
	print_end_test(nameOfFunction);
	Tspi_Context_Close(hContext);
	exit(0);
}
