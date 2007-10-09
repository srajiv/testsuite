/*
 *
 *   Copyright (C) International Business Machines  Corp., 2004-2007
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
 *	Tspi_Context_GetCapability21.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_Context_GetCapability.
 *	The purpose of this test is to verify that Tspi_Context_GetCapability
 *	can be successfully invoked to get the TSS_TCSCAP_PLATFORM_CLASS
 *	capability, subCap subCap TSS_TCSCAP_PROP_ALL_PLATFORMS
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect
 *
 *	Test:	Call GetCapability.
 *		Make sure that it returns the proper return codes
 *
 *	Cleanup:
 *		Free memory associated with the context
 *		Close context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1 and 1.2
 *
 * HISTORY
 *	Author:	Ramon Brandao <ramongb@br.ibm.com>
 *  Date: 8/2007
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdlib.h>

#include "common.h"

int main(int argc, char **argv)
{
	char		version;

	version = parseArgs(argc, argv);
	if (version ==  TESTSUITE_TEST_TSS_1_2)
		main_v1_2(version);
	else if (version == TESTSUITE_TEST_TSS_1_1)
		print_NA();
	else
		print_wrongVersion();
}

int main_v1_2(char version)
{
	char *nameOfFunction = "Tspi_Context_GetCapability21";
	TSS_HCONTEXT hContext;
	TSS_FLAG capArea = TSS_TCSCAP_PLATFORM_CLASS;
	UINT64 offSet;
	UINT32 subCap, i;
	UINT32 ulSubCapLength;
	BYTE *prgbRespData;
	UINT32 pulRespDataLength;
	TSS_RESULT result;
	TSS_PLATFORM_CLASS platClass;
	struct classNames{
		char *className;
	};
	struct classNames platClasses[] = {
			{NULL},
			{"PC_11"},
			{"PC_12"},
			{"PDA_12"},
			{"SERVER_12"},
			{"MOBILE_12"}
	};

	print_begin_test(nameOfFunction);

	//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		exit(result);
	}
	//Connect Context
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect ", result);
		exit(result);
	}

	subCap = TSS_TCSCAP_PROP_ALL_PLATFORMS;
	ulSubCapLength = sizeof(UINT32);

	//Get Capability
	result = Tspi_Context_GetCapability(hContext,
					    capArea, ulSubCapLength,
					    (BYTE *) & subCap,
					    &pulRespDataLength,
					    &prgbRespData);
	if (result != TSS_SUCCESS) {
		if (!checkNonAPI(result)) {
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_Close(hContext);
			exit(result);
		} else {
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_Close(hContext);
			exit(result);
		}
	} else {
		if (pulRespDataLength){
			/* Prints out all platform classes */
			offSet = 0;
			while (offSet < pulRespDataLength){
				result = Trspi_UnloadBlob_TSS_PLATFORM_CLASS(&offSet, prgbRespData, &platClass);
				if (result != TSS_SUCCESS) {
					print_error("Trspi_UnloadBlob_TSS_PLATFORM_CLASS ", result);
					Tspi_Context_Close(hContext);
					exit(result);
				}
				fprintf(stderr, "Host Platform Class ID: %s\n", 
						platClasses[platClass.platformClassSimpleIdentifier].className);
				fprintf(stderr, "Host Platform spec URI: ");
				for (i = 0; i < platClass.platformClassURISize; i++)
					fprintf(stderr, "%c", platClass.pPlatformClassURI[i]);
				fprintf(stderr,"\n");
				free(platClass.pPlatformClassURI);
			}
		}
		result = Tspi_Context_FreeMemory(hContext, prgbRespData);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Context_FreeMemory ", result);
			Tspi_Context_Close(hContext);
			exit(result);
		}
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
