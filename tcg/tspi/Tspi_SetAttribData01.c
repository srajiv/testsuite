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
 *	Tspi_SetAttribData01.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_SetAttribData.
 *	The goal of this test is to return TSS_SUCCESS.
 *		To have it return success, you need to follow the 
 *		algorithm described below.
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
 *	Author:	Kathy Robertson
 *	Date:	June 2004
 *	Email:	klrobert@us.ibm.com
 *
 * RESTRICTIONS
 *	None.
 */


#include <trousers/tss.h>
#include <trousers/trousers.h>
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

	char		*nameOfFunction = "Tspi_SetAttribData01";
	TSS_HKEY	hKey;
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_HPOLICY	hPolicy;
	BYTE           *POPUPSTRING = "bobdbuilder", *utf16_popup;
	UINT32		POPUPSTRINGLEN = strlen(POPUPSTRING);

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
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
				 TSS_POLICY_USAGE, &hPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}

	utf16_popup = char_to_unicode(POPUPSTRING, &POPUPSTRINGLEN);
		//SetAttribData
	result = Tspi_SetAttribData(hPolicy, 
			TSS_TSPATTRIB_POLICY_POPUPSTRING, 
			0, POPUPSTRINGLEN, utf16_popup);
	if (result != TSS_SUCCESS) {
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, hPolicy);
			Tspi_Context_Close(hContext);
			exit(result);
		}
		else{
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, hPolicy);
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}
	else{
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_CloseObject(hContext, hPolicy);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
