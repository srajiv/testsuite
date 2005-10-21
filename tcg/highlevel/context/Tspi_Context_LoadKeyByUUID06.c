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
 *	Tspi_Context_LoadKeyByUUID06.c
 *
 * DESCRIPTION
 *	This test will verify that the TCS can correctly load a chain of
 *	not yet loaded keys in the TCS from PS with none of the keys
 *	requiring auth.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Make sure 3 keys exist in system PS that are children of one
 *		  another
 *
 *	Test:	Attempt to load the grandchild key, check for success
 *
 *	Cleanup:
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
#include <stdlib.h>

#include <trousers/tss.h>
#include "../common/common.h"

char *nameOfFunction = "Tspi_Context_LoadKeyByUUID06";

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


/* create and store keys with the uuids in the @uuids parameter. Unregister
 * any keys in the PS that are already stored. hParentKey should already be
 * loaded and will become the parent of the key stored with uuids[0] */
TSS_RESULT
store_keys(TSS_HCONTEXT hContext, TSS_HKEY hParentKey, TSS_UUID *uuidParent0,
	   TSS_UUID **uuids)
{
	int i;
	TSS_RESULT result;
	TSS_UUID *uuidParent;
	TSS_HKEY hKey;
	TSS_FLAG initFlags;

	for (i = 0; uuids[i]; i++) {
		/* unregister any keys in the PS that are in the way */
		if ((result = Tspi_Context_UnregisterKey(hContext,
							 TSS_PS_TYPE_SYSTEM,
							 *uuids[i], &hKey)) &&
		    (TSS_ERROR_CODE(result) != TSS_E_PS_KEY_NOTFOUND)) {
			print_error("Tspi_Context_UnregisterKey", result);
			print_error_exit(nameOfFunction, err_string(result));
			return result;
		}
	}

	initFlags = TSS_KEY_SIZE_512 | TSS_KEY_TYPE_STORAGE |
		    TSS_KEY_NO_AUTHORIZATION;
	uuidParent = uuidParent0;
	for (i = 0; uuids[i]; i++) {
		/* create the keys and register them */
		if ((result = Tspi_Context_CreateObject(hContext,
							TSS_OBJECT_TYPE_RSAKEY,
							initFlags, &hKey))) {
			print_error("Tspi_Context_CreateObject", result);
			print_error_exit(nameOfFunction, err_string(result));
			return result;
		}

		if ((result = Tspi_Key_CreateKey(hKey, hParentKey, 0))) {
			print_error("Tspi_Context_CreateObject", result);
			print_error_exit(nameOfFunction, err_string(result));
			return result;
		}

		/* load key so that the child can be created */
		if ((result = Tspi_Key_LoadKey(hKey, hParentKey))) {
			print_error("Tspi_Context_CreateObject", result);
			print_error_exit(nameOfFunction, err_string(result));
			return result;
		}

		/* register the new key */
		if ((result = Tspi_Context_RegisterKey(hContext, hKey,
						       TSS_PS_TYPE_SYSTEM,
						       *uuids[i],
						       TSS_PS_TYPE_SYSTEM,
						       *uuidParent))) {
			print_error("Tspi_Context_RegisterKey", result);
			print_error_exit(nameOfFunction, err_string(result));
			return result;
		}
		hParentKey = hKey;
		uuidParent = uuids[i];
	}

	return TSS_SUCCESS;
}

int
main_v1_1(void){

	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_HKEY	hSRK, hKey2;
	TSS_UUID	uuid0, uuid1, uuid2, SRK_UUID = TSS_UUID_SRK;
	TSS_UUID	*uuids[] = { &uuid0, &uuid1, &uuid2, NULL };

	print_begin_test(nameOfFunction);

	memset(&uuid0, 0x5a, sizeof(TSS_UUID));
	memset(&uuid1, 0x5b, sizeof(TSS_UUID));
	memset(&uuid2, 0x5c, sizeof(TSS_UUID));

		//Create Result
	result = connect_load_srk(&hContext, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}

	if ((result = store_keys(hContext, hSRK, &SRK_UUID, uuids))) {
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext,
					    TSS_PS_TYPE_SYSTEM,
					    uuid2, &hKey2);
	if (result != TSS_SUCCESS) {
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(1);
		}
		else{
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(1);
		}
	}
	else{
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
