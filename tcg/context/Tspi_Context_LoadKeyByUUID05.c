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
 *	Tspi_Context_LoadKeyByUUID05.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_Context_LoadByUUID.
 *	The purpose of this test case is to get TSS_E_PS_KEY_NOTFOUND to be returned.
 *		This is done by not initializing the UUID passed in.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *
 *	Test:	Call LoadKeyByUUID. If this is unsuccessful check for 
 *		type of error, and make sure it returns the proper return code
 * 
 *	Cleanup:
 *		Close context
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

#include <trousers/tss.h>
#include "../common/common.h"



int main(int argc, char **argv)
{
	char		*version;

	version = parseArgs(argc, argv);
		// if it is not version 1.1 or 1.2, print error
	if ((0 == strcmp(version, "1.1")) || (0 == strcmp(version, "1.2")))
		main_v1_1();
	else
		print_wrongVersion();
}

int
main_v1_1(void){

	char		*nameOfFunction = "Tspi_Context_LoadKeyByUUID05";
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_HKEY	hSRK;
	TSS_UUID	SRKUUID; // not initalized

	print_begin_test(nameOfFunction);

		//Create Result
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
		//Connect Result
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext,
		TSS_PS_TYPE_SYSTEM, SRKUUID, &hSRK);
	if (TSS_ERROR_CODE(result) != TSS_E_PS_KEY_NOTFOUND) {
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(result);
		}
		else{
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}
	else{
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
