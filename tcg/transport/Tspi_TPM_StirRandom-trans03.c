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
 *	Tspi_TPM_StirRandom01.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_TPM_StirRandom
 *		returns TSS_SUCCESS.
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
 *	EJR, 12/06
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include "common.h"

#define MAX_ENTROPY_SIZE	255

int main(int argc, char **argv)
{
	char version;

	version = parseArgs(argc, argv);
	if (version == TESTSUITE_TEST_TSS_1_2)
		main_v1_2(version);
	else if (version == TESTSUITE_TEST_TSS_1_1)
		print_NA();
	else
		print_wrongVersion();
}

int
main_v1_2(char version)
{
	char *function = "Tspi_TPM_StirRandom-trans03";
	BYTE entropy[MAX_ENTROPY_SIZE];
	TSS_HCONTEXT hContext;
	TSS_HTPM hTPM;
	TSS_RESULT result;
	int i;
	TSS_HKEY	hSRK, hWrappingKey;

	print_begin_test(function);

	/* seed entropy with time */
	srand(time(0));

	result = connect_load_all(&hContext, &hSRK, &hTPM);
	if ( result != TSS_SUCCESS )
	{
		print_error( "connect_load_all", (result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Testsuite_Transport_Init(hContext, hSRK, hTPM, TRUE, TRUE, &hWrappingKey,
					  NULL);
	if (result != TSS_SUCCESS) {
		print_error("Testsuite_Transport_Init", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	for (i = 0; i < MAX_ENTROPY_SIZE; i++)
		entropy[i] = (rand() % 256);

	/* Get random number */
	result = Tspi_TPM_StirRandom(hTPM, MAX_ENTROPY_SIZE, entropy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_StirRandom", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Testsuite_Transport_Final(hContext, 0);
	if (result != TSS_SUCCESS)
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
