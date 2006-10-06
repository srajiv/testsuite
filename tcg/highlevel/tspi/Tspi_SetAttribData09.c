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
 *	Tspi_SetAttribData09.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_SetAttribData of public key data succeeds.
 *
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect
 *		Create Object
 *
 *	Test:	Call SetAttribData. If it is not a success
 *		Make sure that it returns the proper return codes
 *
 *	Cleanup:
 *		Free memory associated with hContext
 *		Close hPolicy object
 *		Close context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1
 *
 * HISTORY
 *	Author:	Kent Yoder
 *
 * RESTRICTIONS
 *	None.
 */


#include <trousers/tss.h>
#include "../common/common.h"



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

	char			*nameOfFunction = "Tspi_SetAttribData09";
	TSS_HKEY		hKey;
	TSS_HCONTEXT		hContext;
	TSS_RESULT		result;
	BYTE			pub_exp[] = { 1, 0, 1 }; // 65537
	TCPA_RSA_KEY_PARMS	parms = { TCPA_ALG_RSA, 2, (UINT16)sizeof(pub_exp), pub_exp };
	UINT32			blobLen;
	BYTE			blob[1024];
	UINT16			offset;
	BYTE			n[256];
	TCPA_PUBKEY		pub = {
		{
			TCPA_ALG_RSA,
			TCPA_ES_RSAESOAEP_SHA1_MGF1,
			TCPA_SS_RSASSAPKCS1v15_SHA1,
			(UINT32)sizeof(parms),
			(BYTE *)&parms
		},
		{
			(UINT32)sizeof(n),
			n,
		}
	};

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
		Tspi_Context_Close(hContext);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
		//Create Object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
					TSS_KEY_SIZE_2048, &hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}

	TestSuite_LoadBlob_PUBKEY(&offset, blob, &pub);
	if (result != TSS_SUCCESS) {
		print_error("TestSuite_LoadBlob_PUBKEY", result);
		Tspi_Context_Close(hContext);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
	blobLen = (UINT32)offset;

		//SetAttribData
	result = Tspi_SetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
				    TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
				    blobLen, blob);
	if (result != TSS_SUCCESS) {
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_Close(hContext);
			exit(result);
		}
		else{
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}
	else{
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
