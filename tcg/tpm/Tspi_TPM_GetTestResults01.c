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
 *	Tspi_TPM_GetTestResults01.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_TPM_GetTestResults
 *	The purpose of this test case is to get TSS_SUCCESS to be returned. 
 *		This should be returned when the algorithm described below
 *		is followed.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		GetTPMObject
 *
 *	Test:	Call GetTestResults. If this is unsuccessful check for 
 *		type of error, and make sure it returns the proper return code
 * 
 *	Cleanup:
 *		Print errno log and/or timing stats if options given
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

	char		*nameOfFunction = "Tspi_TPM_GetTestResults01";
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_HTPM	hTPM;
	UINT32		TestResultLength;
	BYTE*		prgbTestResult;

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
		//Get Tpm Object
	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetTpmObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get Test Result
	result = Tspi_TPM_GetTestResult(hTPM, &TestResultLength, &prgbTestResult);
	if (result != TSS_SUCCESS) {
		if((TSS_ERROR_CODE(result) == TSS_E_INVALID_HANDLE) ||
			(TSS_ERROR_CODE(result) == TSS_E_INTERNAL_ERROR) ||
			(TSS_ERROR_CODE(result) == TSS_E_BAD_PARAMETER) ||
			(TSS_ERROR_CODE(result) == TSS_E_KEY_NO_MIGRATION_POLICY) ||
			(TSS_ERROR_CODE(result) == TSS_E_FAIL) ||
			(TSS_ERROR_CODE(result) == TSS_E_NOTIMPL) ||
			(TSS_ERROR_CODE(result) == TSS_E_PS_KEY_NOTFOUND) ||
			(TSS_ERROR_CODE(result) == TSS_E_KEY_ALREADY_REGISTERED) ||
			(TSS_ERROR_CODE(result) == TSS_E_CANCELED) ||
			(TSS_ERROR_CODE(result) == TSS_E_TIMEOUT) ||
			(TSS_ERROR_CODE(result) == TSS_E_OUTOFMEMORY) ||
			(TSS_ERROR_CODE(result) == TSS_E_TPM_UNEXPECTED) ||
			(TSS_ERROR_CODE(result) == TSS_E_COMM_FAILURE) ||
			(TSS_ERROR_CODE(result) == TSS_E_TPM_UNSUPPORTED_FEATURE)){

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
		result = Tspi_Context_FreeMemory(hContext, prgbTestResult);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Context_FreeMemory ", result);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
