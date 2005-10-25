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
 *	Tspi_TPM_GetEventLog05.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_TPM_GetEventLog.
 *	The purpose of this test case is to return TSS_SUCCESS.
 *		To ensure that this return code is properly returned
 *		it is necessary to follow the algorithm described
 *		below.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		GetTPMObject
 *
 *	Test:	Call TPM_GetEventLog. If this is unsuccessful check for
 *		type of error, and make sure it returns the proper return code
 *
 *	Cleanup:
 *		Close Context
 *		Print error/success message.
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
	char		*nameOfFunction = "Tspi_TPM_GetEventLog05";
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_HTPM	hTPM;
	UINT32		ulEventNumber, i, j;
	TSS_PCR_EVENT*	PCREvents;

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
		//Get TPM Object
	result = Tspi_Context_GetTpmObject(hContext,  &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetTpmObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get Event
	result = Tspi_TPM_GetEventLog(hTPM, &ulEventNumber,
				&PCREvents);
	if (result != TSS_SUCCESS) {
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
		}
		else{
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
		}
	}
	printf("There are %d events:\n", ulEventNumber);
	printf("PCR SHA1\t\t\t\t     Type Event Data\n");

	for (i = 0; i < ulEventNumber; i++) {
		printf("%*d ", 3, PCREvents[i].ulPcrIndex);
		for (j=0; j<PCREvents[i].ulPcrValueLength; j++)
			printf("%02x", PCREvents[i].rgbPcrValue[j] & 0xff);
		if (j < 20)
			while (j < 20) {
				printf(" ");
				j++;
			}

		printf(" %*d ", 4, PCREvents[i].eventType);
		if (PCREvents[i].ulEventLength == 0)
			printf("NONE\n");
		else
			for (j=0; j<PCREvents[i].ulEventLength; j++)
				printf("%02x", PCREvents[i].rgbEvent[j] & 0xff);

			printf("\n");
	}
}
