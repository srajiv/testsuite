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
 *	Tspi_Context_CloseObject04.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_Context_CloseObject.
 *	The purpose of this test case is to get TSS_E_INVALID_HANDLE to be
 *		returned. This is accomplished by passing in incorrect parameters to 
 *		Tspi_Context_CloseObject. This test case creates
 *		a one context called WrongContext and connects it 
 *		to a signature key called wrongsignature key. Then 
 *		this test case creates hContext, and connect it 
 *		to the proper signature key. Then this test case 
 *		calls Tspi_Context_CloseObject with hContext and the
 *		wrong signature key which should return TSS_E_INVALID_HANDLE
 *
 * ALGORITHM
 *	Setup:
 *		Create Wrong Context
 *		Connect Wrong Context
 *		Create Context
 *		Connect Context
 *		Create Object
 *		Create Wrong Context
 *
 *	Test:	Call to Close Object.
 *		Make sure that it returns the proper return codes
 *	Cleanup:
 *		Free Memory associated with the context
 *		Close the hWrongSignatureKey object
 *		Close hSignatureKey object
 * 		Close context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1 and 1.2
 *
 * HISTORY
 *	Author:	Kathy Robertson
 *	Date:	June 2004
 *	Email:	klrobert@us.ibm.com
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdlib.h>

#include "common.h"



int main(int argc, char **argv)
{
	char		*version;

	version = parseArgs( argc, argv );
		// if it is not version 1.1 or 1.2, print error
	if ((0 == strcmp(version, "1.1")) || (0 == strcmp(version, "1.2")))
		main_v1_1();
	else
		print_wrongVersion();
}

int
main_v1_1(void){

	char		*nameOfFunction = "Tspi_Context_CloseObject04";
	TSS_HCONTEXT	hContext;
	TSS_HKEY	hSignatureKey;
	TSS_HTPM	hTPM;
	TSS_RESULT	connectResult;
	TSS_RESULT	result;
	TSS_HCONTEXT	hWrongContext;
	TSS_HKEY	hWrongSignatureKey;

	print_begin_test(nameOfFunction);
	
		//Create Wrong Context
	result = Tspi_Context_Create(&hWrongContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
		//Connect Wrong Context
	result = Tspi_Context_Connect(hWrongContext, get_server(GLOBALSERVER));
	if(result != TSS_SUCCESS){
		print_error("Tspi_Context_Connect ", result);
		Tspi_Context_Close(hWrongContext);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
		//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hWrongContext);
		exit(result);
	}
		//Connect Context
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if(result != TSS_SUCCESS){
		print_error("Tspi_Context_Connect ", result);
		Tspi_Context_Close(hContext);
		Tspi_Context_Close(hWrongContext);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
		//Create Wrong Object
	result = Tspi_Context_CreateObject(hWrongContext,
			TSS_OBJECT_TYPE_RSAKEY,TSS_KEY_SIZE_2048 
			| TSS_KEY_TYPE_SIGNING | TSS_KEY_MIGRATABLE,
			&hWrongSignatureKey);
	if(result != TSS_SUCCESS){
		print_error("Tspi_Context_CreateObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		Tspi_Context_Close(hWrongContext);
		exit(result);
	}
		//Create Correct Object
	result = Tspi_Context_CreateObject(hContext, 
			TSS_OBJECT_TYPE_RSAKEY,TSS_KEY_SIZE_2048 
			| TSS_KEY_TYPE_SIGNING | TSS_KEY_MIGRATABLE,
			&hSignatureKey);
	if(result != TSS_SUCCESS){
		print_error("Tspi_Context_CreateObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		Tspi_Context_Close(hWrongContext);
		result = Tspi_Context_CloseObject(hWrongContext, hWrongSignatureKey);
		exit(result);
	}
		//Close Object
	result = Tspi_Context_CloseObject(hContext, hWrongSignatureKey);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_HANDLE) {
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, hSignatureKey);
			Tspi_Context_CloseObject(hWrongContext, hWrongSignatureKey);
			Tspi_Context_Close(hContext);
			exit(result);
		}
		else{
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hWrongContext, hWrongSignatureKey);
			Tspi_Context_CloseObject(hContext, hSignatureKey);
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}
	else{
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_CloseObject(hWrongContext, hWrongSignatureKey);
		Tspi_Context_CloseObject(hContext, hSignatureKey);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
