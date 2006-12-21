/*
 *
 *   Copyright IBM Corp., 2004-2006
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
 *	Tspi_TPM_StirRandom04.c
 *
 * DESCRIPTION
 *	This test will verify that calling Tspi_TPM_StirRandom
 *		with an entropy that is too large returns TSS_E_BAD_PARAMETER.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Get TPM Object
 *		Get Entropy
 *
 *	Test:
 *		Call TPM_StirRandom then if it does not succeed
 *		Make sure that it returns the proper return codes
 *		Print results
 *
 *	Cleanup:
 *		Free memory relating to hContext
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
 *	EJR, emilyr@us.ibm.com, 12/06
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include <trousers/tss.h>
#include "../common/common.h"

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
	char *function = "Tspi_TPM_StirRandom04";
	BYTE *entropy;
	TSS_HCONTEXT hContext;
	TSS_HTPM hTPM;
	TSS_RESULT result;
	int i;

	print_begin_test(function);

	/* seed entropy with time */
	srand(time(0));

	/* Create Context */
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create", result);
		print_error_exit(function, err_string(result));
		exit(result);
	}
	/* Connect to Context */
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	/* Retrieve TPM object of context */
	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetTpmObject", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	entropy = (BYTE *) malloc(257);
	for (i = 0; i < 256; i++) {
		entropy[i] = (rand() % 100);
	}

	/* Seed PRND on TPM with sort of random entropy */
	result = Tspi_TPM_StirRandom(hTPM, 256, entropy);
	if (TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER)
		if (!(checkNonAPI(result))) 
			print_error(function, result);
		else 
			print_error_nonapi(function, result);
	else 
		print_success(function, result);

	print_end_test(function);
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_Close(hContext);
	exit(result);
}