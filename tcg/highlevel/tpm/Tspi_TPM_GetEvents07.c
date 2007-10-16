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
 *	Tspi_TPM_GetEvents07.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_TPM_GetEvents
 *	The purpose of this test case is to test whether passing a NULL handle
 *	to receive events will get the total number of PCR events.
 *
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		GetTPMObject
 *
 *	Test:	Call GetEvents. If this is unsuccessful check for
 *		type of error, and make sure it returns the proper return code
 *
 *	Cleanup:
 *		Close Context
 *		Print erorr/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1
 *
 * HISTORY
 *    Kent Yoder, shpedoikal@gmail.com, 10/05
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
	char		*nameOfFunction = "Tspi_TPM_GetEvents07";
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_HTPM	hTPM;
	UINT32		ulPcrIndex, ulNumPcrs, i, j, len;
	UINT32		ulStartNumber	= 0;
	UINT32		ulEventNumber	= -1;
	TSS_PCR_EVENT*  prgbPcrEvents;
	BYTE		*numPcrs;
	UINT32		subcap;

	print_begin_test(nameOfFunction);

		//Create Result
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		exit(result);
	}
		//Connect Result
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get TPM Object
	result = Tspi_Context_GetTpmObject(hContext,  &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetTpmObject ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	len = sizeof(UINT32);
	subcap = TSS_TPMCAP_PROP_PCR;

	result = Tspi_TPM_GetCapability(hTPM, TSS_TPMCAP_PROPERTY, sizeof(UINT32),
			(BYTE *)&subcap, &len, &numPcrs);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_GetCapability ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	ulNumPcrs = (UINT32)*numPcrs;

	printf("PCR Number_of_Events\n");
	for (ulPcrIndex = 0; ulPcrIndex < ulNumPcrs; ulPcrIndex++) {
		//Get Events
		result = Tspi_TPM_GetEvents(hTPM, ulPcrIndex,
				ulStartNumber,&ulEventNumber,
				NULL);
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

		printf("%*u %u\n", 3, ulPcrIndex, ulEventNumber);
	}

	exit(result);
}
