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
 *	Tspi_Context_Connect04.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_Context_Connect can connect to several
 *	different locations, each which should be the local TPM.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *
 *	Test:	Call Connect Context twice then if it is not a success
 *		Make sure that it returns the proper return codes
 *
 *	Cleanup:
 *		Close context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1
 *
 *
 * HISTORY
 *	Author:	Kent Yoder
 *	Date:	July 2005
 *	Email:	kyoder@users.sf.net
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

	version = parseArgs( argc, argv );
		// if it is not version 1.1, print error
	if(strcmp(version, "1.1")){
		print_wrongVersion();
	}
	else{
		main_v1_1();
	}
}

TSS_RESULT connect_test(UNICODE *);
char *nameOfFunction = "Tspi_Context_Connect04";

#define NUM_DESTS	3

BYTE *dests[NUM_DESTS] = {
	NULL,
	(BYTE *)"l\0o\0c\0a\0l\0h\0o\0s\0t\0\0\0",
	(BYTE *)"1\0002\0007\000.\0000\000.\0000\000.\0001\0\0\0"
};

int
main_v1_1(void){

	TSS_RESULT	result;
	UINT32 i;

	print_begin_test(nameOfFunction);

	for (i = 0; i < NUM_DESTS; i++)
		if ((result = connect_test((UNICODE *)dests[i])))
			exit(result);

	print_success(nameOfFunction, result);
	print_end_test(nameOfFunction);
	exit(0);
}

TSS_RESULT
connect_test(UNICODE *dest)
{
	TSS_HCONTEXT	hContext, hContext2;
	TSS_RESULT	result;

		//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
		// Try the explicit NULL destination
	result = Tspi_Context_Connect(hContext, dest);
	if (result != TSS_SUCCESS) {
		if(!checkNonAPI(result)){
			print_error("Tspi_Context_Connect", result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(result);
		}
		else{
			print_error_nonapi("Tspi_Context_Connect", result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}
	else{
		print_success(nameOfFunction, result);
	}

	Tspi_Context_Close(hContext);
		//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
}
