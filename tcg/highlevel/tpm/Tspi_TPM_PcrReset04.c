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
 *	Tspi_TPM_PcrReset04.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_TPM_PcrReset resets a PCR value.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		GetTPMObject
 *		Create PCRs object
 *		Select a PCR index
 *		Call PcrReset
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

	char		*nameOfFunction = "Tspi_TPM_PcrReset04";
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_HPCRS	hPcrs;
	TSS_RESULT	result;
	UINT32		ulPcrValueLength;
	BYTE		*rgbPcrValue[3], *rand;


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

	result = Tspi_TPM_GetRandom( hTPM, 20, &rand );
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_GetRandom", result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS, 0, &hPcrs);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_PcrComposite_SelectPcrIndex(hPcrs, 16);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_PcrComposite_SelectPcrIndex", result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Reset the PCR
	result = Tspi_TPM_PcrReset(hTPM, hPcrs);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_PcrReset", result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Read its value
	result = Tspi_TPM_PcrRead( hTPM, 16, &ulPcrValueLength, &rgbPcrValue[0] );
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_PcrRead", result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Extend with some data
	result = Tspi_TPM_PcrExtend(hTPM, 16, 20, rand, NULL, &ulPcrValueLength, &rgbPcrValue[1] );
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_PcrExtend", result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Reset the PCR
	result = Tspi_TPM_PcrReset(hTPM, hPcrs);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_PcrReset", result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Read its value again
	result = Tspi_TPM_PcrRead( hTPM, 16, &ulPcrValueLength, &rgbPcrValue[2] );
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_PcrRead", result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	Tspi_Context_Close(hContext);

	// Test 1: Reset PCR values should be the same
	if (!memcmp(rgbPcrValue[0], rgbPcrValue[2], ulPcrValueLength))
		print_success(nameOfFunction, result);
	else {
		print_error(nameOfFunction, result);
		result = TSS_E_FAIL;
	}

	// Test 2: Extended PCR value should be different
	if (memcmp(rgbPcrValue[0], rgbPcrValue[1], ulPcrValueLength))
		print_success(nameOfFunction, result);
	else {
		print_error(nameOfFunction, result);
		result = TSS_E_FAIL;
	}

	print_end_test(nameOfFunction);
	exit(result);
}
