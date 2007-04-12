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
 *	Tspi_GetAttribData19.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_GetAttribData returns the correct UUID
 *	when its retrieved from a key that was stored in PS.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect
 *		Create Object
 *		Load Key By UUID for SRK
 *
 *	Test:	Call GetAttribData. If it is not a success
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
 *	Kent Yoder, shpedoikal@gmail.com
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

	char		*nameOfFunction = "Tspi_GetAttribData19";
	TSS_FLAG	initFlags;
	TSS_HKEY	hKey;
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_HKEY	hSRK;
	BYTE*		uuid;
	UINT32		uuidLength;
	int		rc;
	TSS_UUID	null_uuid, key_uuid;
	initFlags	= TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048  |
			TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
			TSS_KEY_NOT_MIGRATABLE;

	memset(&null_uuid, 0, sizeof(TSS_UUID));
	memset(&key_uuid, 0x7f, sizeof(TSS_UUID));

	print_begin_test(nameOfFunction);

		//Create Context and connect
	result = connect_load_srk(&hContext, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("connect_load_srk", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
		//Create Key Object
	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   initFlags, &hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Create Key in the TPM
	result = Tspi_Key_CreateKey(hKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Call GetAttribData, uuid should be all 0's
	result = Tspi_GetAttribData(hKey,
				    TSS_TSPATTRIB_KEY_UUID, 0,
				    &uuidLength, &uuid);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetAttribData", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Check length and data
	if (uuidLength != sizeof(TSS_UUID)) {
		print_verifyerr("uuid length from Tspi_GetAttribData", 0, 1);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	if ((rc = memcmp(uuid, &null_uuid, uuidLength))) {
		print_verifyerr("a null uuid from Tspi_GetAttribData", 0, rc);
		print_hex(uuid, sizeof(TSS_UUID));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	Tspi_Context_FreeMemory(hContext, uuid);

register_key:
		//Register Key
	result = Tspi_Context_RegisterKey(hContext, hKey, TSS_PS_TYPE_SYSTEM,
					  key_uuid, TSS_PS_TYPE_SYSTEM,
					  SRK_UUID);
	if (TSS_ERROR_CODE(result) == TSS_E_KEY_ALREADY_REGISTERED) {
		result = Tspi_Context_UnregisterKey(hContext,
						    TSS_PS_TYPE_SYSTEM,
						    key_uuid, &hKey);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Context_UnregisterKey", result);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			exit(result);
		}
		goto register_key;
	} else if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_RegisterKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Close the object
	result = Tspi_Context_CloseObject(hContext, hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CloseObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	hKey = 0;
		//Load the key by UUID from PS
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
					    key_uuid, &hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Call GetAttribData, uuid should be equal to key_uuid
	result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_UUID, 0,
				    &uuidLength, &uuid);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetAttribData", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Check length and data
	if (uuidLength != sizeof(TSS_UUID)) {
		print_verifyerr("uuid length from Tspi_GetAttribData", 0, 1);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	if ((rc = memcmp(uuid, &key_uuid, uuidLength))) {
		print_verifyerr("key's uuid from Tspi_GetAttribData", 0, rc);
		print_hex((BYTE *)&key_uuid, sizeof(TSS_UUID));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	print_success(nameOfFunction, result);
	print_end_test(nameOfFunction);
	Tspi_Context_Close(hContext);
	exit(0);
}
