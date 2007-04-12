/*
 *
 *   Copyright (C) International Business Machines  Corp., 2005
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
 *	Tspi_TPM_PcrExtend05.c
 *
 * DESCRIPTION
 *	This test will extend every PCR on the system with some data and
 *	pass in a PCR event for each as well. This is useful mostly in
 *	testing GetPcrEvent calls.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		GetTPMObject
 *
 *	Test:   Call PcrExtend. If this is unsuccessful check for
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

#define EVENT_DATA_SIZE 32

main_v1_1(void){

	char		*nameOfFunction = "Tspi_TPM_PcrExtend05";
	TSS_HCONTEXT	hContext;
	TSS_HKEY	hSRK;
	TSS_HTPM	hTPM;
	BYTE		*pcrValue;
	UINT32		ulPcrValueLength, subCap, numPcrs, i, j;
	BYTE		*NewPcrValue, *rgbNumPcrs;
	TSS_RESULT	result;
	BYTE		event_data[EVENT_DATA_SIZE];

	TSS_PCR_EVENT event;
	memset(&event, 0, sizeof(TSS_PCR_EVENT));
	event.rgbEvent = event_data;
	event.ulEventLength = EVENT_DATA_SIZE;
	event.ulPcrValueLength = 20;

	print_begin_test(nameOfFunction);


		//Create Context
	result	= connect_load_all(&hContext, &hSRK, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("connect_load_all", result);
		exit(result);
	}

	result = Tspi_TPM_GetRandom(hTPM, 20, &pcrValue);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_GetRandom", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	event.rgbPcrValue = pcrValue;

	subCap = TSS_TPMCAP_PROP_PCR;
		// Retrieve number of PCR's from the TPM
	result = Tspi_TPM_GetCapability(hTPM, TSS_TPMCAP_PROPERTY,
					sizeof(UINT32), (BYTE *)&subCap,
					&ulPcrValueLength, &rgbNumPcrs);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_GetTpmObject", result );
		print_error_exit(nameOfFunction, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	if (ulPcrValueLength != sizeof(UINT32)) {
		printf("GetCapability(TSS_TPMCAP_PROP_PCR) returns value !="
		       " sizeof(UINT32) !");
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	numPcrs = *(UINT32 *)rgbNumPcrs;

	for (i = 0; i < numPcrs; i++) {
		memset(&event_data, i, EVENT_DATA_SIZE);
		event.ulPcrIndex = i;

		//Call PcrExtend
		result = Tspi_TPM_PcrExtend(hTPM, i, 20, pcrValue, &event,
					    &ulPcrValueLength, &NewPcrValue);
		if (result) {
			print_error_exit(nameOfFunction, err_string(result));
			break;
		}
	}
	if (result != TSS_SUCCESS) {
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
