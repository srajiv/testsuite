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
 *	Tspi_TPM_PcrReset02.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_TPM_PcrReset returns an invalid handle error
 *	when it should.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		GetTPMObject
 *		Create PCRs object
 *		Select a PCR index
 *		Call PcrReset with a bad context handle
 *
 *	Test:   Call PcrReset. If this is unsuccessful check for
 *		type of error, and make sure it returns the proper return code
 *
 *	Cleanup:
 *		Close Context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1
 *
 * HISTORY
 *	Author:	Kent Yoder, 04/2007
 *
 * RESTRICTIONS
 *	None.
 */

#include "common.h"


int main(int argc, char **argv)
{
	char version;

	version = parseArgs( argc, argv );
	if (version == TESTSUITE_TEST_TSS_1_2)
		main_v1_2(version);
	else if (version)
		print_NA();
	else
		print_wrongVersion();
}

main_v1_2(char version){

	char		*nameOfFunction = "Tspi_TPM_PcrReset02";
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_RESULT	result;


	print_begin_test(nameOfFunction);

		//Create Context
	result	= Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		print_end_test(nameOfFunction);
		exit(result);
	}
		//Connect Context
	result	= Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get TPM Object
	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetTpmObject", result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Call PcrReset
	result = Tspi_TPM_PcrReset(hTPM, 0xffffffff);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_HANDLE) {
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
	} else {
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
