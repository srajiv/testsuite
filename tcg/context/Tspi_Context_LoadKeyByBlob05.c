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
 *	Tspi_Context_LoadKeyByBlob05.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_Context_LoadKeyByBlob
 *	using a RSA key does not segfault. This test ensures that
 *	the OpenSSL TPM engine does not cause openssl to segfault
 *	when the user give the wrong key file as input.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Load SRK by UUID
 *		Get Policy Object
 *		Set Secret
 *		Get Attrib Data (blob)
 *
 *	Test:
 *		Call Context_LoadKeyByBlob then if it does not succeed
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
 *      This test case is currently only implemented for v1.1 or 1.2
 *
 * HISTORY
 *	Megan Schneider, mschnei@us.ibm.com, 6/04.
 *	EJR, emilyr@us.ibm.com, 12/06.
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include <stdlib.h>

#include "common.h"


int main(int argc, char **argv)
{
	char *version;

	version = parseArgs(argc, argv);
	/* if it is not version 1.1 or 1.2, print error */
	if ((0 == strcmp(version, "1.1")) || (0 == strcmp(version, "1.2")))
		main_v1_1();
	else
		print_wrongVersion();
}

int main_v1_1(void)
{
	char *function = "Tspi_Context_LoadKeyByBlob05";
	TSS_HCONTEXT hContext;
	TSS_HKEY hSRK;
	TSS_HKEY hMSigningKey;
	BYTE *keyBlob =
	    "-----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEA43EdJcHeFZXCHHCmJX3z1wIOqJCagSRDdkg1qoRWyna02TzY CY2rNH9+5TtzvDqg5Nh5+HTIfKpRy67PabZxn/yrXT/STbWm0HSMB2zhFFMpelRV 7BRp8Bi/7d71/jubVIUE/a+TFLOI5iooFIA0DX2nlK+vyICE4aZrDW8UPEpqbWuR J7BCRXcTx6GkkQlU5UvoNnN3cC2sgIgG5MHOzZj+nxs+ombvkFu1FPr8MYR+d0jE amqr3KdLnmJSxY4wgWehDUOds+JX7i6oWNnrX7E/aY6lCRLuKgZH00zZkrScVfI2 arSRZj5NMTiI0BNmzjqfmm6silp2LHx0CeMAjQIDAQABAoIBAFTczrhY1smNAElm Ssfwb/wIe3mvwsZuxnEqzkNab5vJoP7xcdZWssu6ypkzjqJr6b6ZeyEWSfwh/LUX +7IA7fJ472OyvYBbR+u9oMXgfTb9NJu9PfYBQ+nfAjX6HCUJDpMBsvQI/8MYnfrr PdswXrut58pVpywTsAEV/BmeGZnIof8IcD/dd6GjluRGrZaD7hlEe50CiwzAUeJi kceRS/eBIxblzvG3xsL1+KPlbgzXbDU+GLmCXAMzrImcZyf9rE4+iYAB0t897BbQ VZzTXtXKQCDMJKmG5dzWt3qyKZxrzlwFuv/6QUoiYEp3X2BdSPomJsCGXFuqNAFx 0s9smSECgYEA/9HryCdw2s5PAwzFtAFshGGhyn0mxIQrmSW5l0hs57kw2+angvUR OGXcRUgU/vV32S/KN072wuA/wuBlkl1wpkhYRF5O3ASddXyk0EiQIP17j64VYgnZ lfeeS8emVCjsIEiBkWCiSOTDZ3TX8yd5PH5XN2bnt5XL41aeXbOiFikCgYEA45oU zy9chh4lbpt/kpQDvWqrNMWD7t1bpxjjb2kK/EgaF8+3JSMNSRYowc5SSs63TSId 2Utz2i/yaLQtrQuXcvYktg1XfdgsglRuFgdA7UPOgRTodZOTQlx2/m2aT533kPYF EHnWIrq1HIWotSb9AAiPrS9xbFgfT9OeU/c4u8UCgYB5FbdwaZq1NmmXm/gIF5Rx pHScD1jGM3kfaAfMX2+Mzs8dhrNK/QxFkZENCe1GMJGlr0UboLiTzOjhKK1q9edY DW4aDjltUpHlBjZMj8wIkXJms5NTcC4ZGbdHTxyfQS9iqG8LjJ3DuuPymA+O++Qa igJmKsMK1lBHLryOxXO24QKBgCAzVG5bjQOMkE8twMbEGiNaTA6TQy8wMh9Z7hN9 EQjQSqDDym1+oAqPEAUbY5kh1d0bzo1Hl4Ru9CTMGQo6cZraKCd5i79KLkHiIBEN xanLxhONGbZIwrTI0Cz+5K4O80+W/vBtzFXthGIcptm6QmEW1PzzkWB6tzNcBTJr 76LhAoGBAJhnp3tRu9WZdmlm1lln1d89MCNrvzMIRGVXFf2Bv+aNs1+ke8p0ZRmL sQ2tD7+K6+QP7y0PHLcB1ePdHbcHv7dF7X3fMITzW4P5hRhES2D0mPHjKCpeAdiY 3sUBjl9Yd/tXpST8G4883icImR3c3rKMzSxsOU6i57+PXDglxV+D -----END RSA PRIVATE KEY-----";
	UINT32 blobLength;
	TSS_RESULT result;
	TSS_HPOLICY srkUsagePolicy;
	UINT32 exitCode = 0;

	print_begin_test(function);

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
	/* Load Key By UUID */
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
					    SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID (hSRK)", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	/* Get Policy Object */
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE,
				      &srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	/* Set Secret */
	result =
	    Tspi_Policy_SetSecret(srkUsagePolicy,
				  TESTSUITE_SRK_SECRET_MODE,
				  TESTSUITE_SRK_SECRET_LEN,
				  TESTSUITE_SRK_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret (1)", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	/* Create Signing Key */
	result =
	    Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
				      TSS_KEY_SIZE_2048 |
				      TSS_KEY_TYPE_SIGNING,
				      &hMSigningKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject (Signing Key)",
			    result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_CreateKey(hMSigningKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey (Signing Key)", result);
		print_error_exit(function, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	blobLength = strlen(keyBlob);

	/* Load Key Blob */
	result = Tspi_Context_LoadKeyByBlob(hContext, hSRK, blobLength,
					    keyBlob, &hMSigningKey);
	if (TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER) {
		exitCode = result;
		if (!(checkNonAPI(result)))
			print_error(function, result);
		else
			print_error_nonapi(function, result);
	} else {
		print_success(function, result);
	}

	print_end_test(function);
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_Close(hContext);
	exit(exitCode);
}
