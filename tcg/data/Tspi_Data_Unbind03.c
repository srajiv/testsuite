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
 *	Tspi_Data_Unbind03.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_Data_Unbind
 *		returns TSS_E_BAD_PARAMETER when one
 *		of the last two parameters is NULL.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Load Key By UUID
 *
 *	Test:
 *		Call Data_Unbind then if it does not succeed
 *		Make sure that it returns the proper return codes
 *		Print results
 *
 *	Cleanup:
 *		Free memory related to hContext
 *		Close context
 *
 * USAGE
 *      First parameter is --options
 *                         -v or --version
 *      Second parameter is the version of the test case to be run
 *      This test case is currently only implemented for v1.1 and 1.2
 *
 * HISTORY
 *      Megan Schneider, mschnei@us.ibm.com, 6/04.
 *      Kent Yoder, shpedoikal@gmail.com, 09/14/04
 *        Commented out unneeded code.
 *	EJR, ejratl@gmail.com, 8/10/2006, cleanup and 1.2
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include "common.h"


int main(int argc, char **argv)
{
	char *version;

	version = parseArgs(argc, argv);
	// if it is not version 1.1 or 1.2, print error
	if ((0 == strcmp(version, "1.1")) || (0 == strcmp(version, "1.2")))
		main_v1_1();
	else
		print_wrongVersion();
}

int main_v1_1(void)
{
	char *function = "Tspi_Data_Unbind03";
	TSS_HCONTEXT hContext;
	TSS_HKEY hSRK;
	TSS_HKEY hKey;
	TSS_HENCDATA hEncData;
	UINT32 pulDataLength;
	BYTE rgbDataToBind[32] =
	    { 0, 1, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4,
5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7 };
	UINT32 ulDataLength = 32, exitCode = 0;
	TSS_UUID uuid;
	TSS_RESULT result;
	TSS_FLAG initFlags = TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048 |
	    TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
	    TSS_KEY_NOT_MIGRATABLE;

	print_begin_test(function);

	// Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create", result);
		print_error_exit(function, err_string(result));
		exit(result);
	}
	// Connect to Context
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
					    SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID (hSRK)", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Data_Unbind(hEncData, hSRK, &pulDataLength, NULL);
	if (TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER) {
		if (!(checkNonAPI(result)))
			print_error(function, result);
		else
			print_error_nonapi(function, result);
		exitCode = result;
	} else {
		print_success(function, result);
	}

	print_end_test(function);
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_Close(hContext);
	exit(exitCode);
}
