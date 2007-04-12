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
 *	Tspi_ChangeSRKAuthAndReregister
 *
 * DESCRIPTION
 *	This test will verify that changing the authdatausage for the SRK from 0 to 1 works. It then
 *	will unregister the SRK from TCS PS and re-register a new blob with authDataUsage=TRUE set.
 *	It will then pull that blob out os TCS PS and verify that the authdata usage is correct.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect
 *		Load Key By UUID for hSRK
 *		Get Policy Object for the srk
 *		Set Secret
 *		Create Storage Key
 *		Create Signing Key
 *		Load keys
 *		Get Default Policy for the hPolicy
 *
 *	Test:	Call ChangeAuth. If it is not a success
 *		Make sure that it returns the proper return codes
 *
 *	Cleanup:
 *		Free memory associated with the context
 *		Close hMSigningKey Object
 *		Close context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1
 *
 * HISTORY
 *    Kent Yoder <shpedoikal@gmail.com>, 11/2006
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

int
main_v1_1(void){

	char		*nameOfFunction = "Tspi_ChangeSRKAuthAndReregister";
	TSS_HKEY	hPsSRK, hSRK;
	TSS_HPOLICY	srkUsagePolicy, hTPMPolicy, hNewPolicy;
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_HTPM	hTPM;
	UINT32		usageauth;
	TSS_UUID	NULL_UUID = {0,0,0,0,0,{0,0,0,0,0,0}};

	print_begin_test(nameOfFunction);

		//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
		//Connect Context
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}


	// Set up the SRK

		//Load SRK By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID for hSRK", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_GetAttribUint32(hSRK, TSS_TSPATTRIB_KEY_INFO,
				      TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE, &usageauth);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	if (usageauth) {
		fprintf(stderr, "Usage auth on the SRK is TRUE. Exiting this testcase with "
			"success without having tested anything.\nTo use this testcase, set "
			"your TPM's SRK's authdatausage to 0.\n");
		Tspi_Context_Close(hContext);
		exit(0);
	}
#if 0
#ifndef TESTSUITE_NOAUTH_SRK
		//Get Policy Object
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret
	result = Tspi_Policy_SetSecret(srkUsagePolicy, TESTSUITE_SRK_SECRET_MODE,
				TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
#endif
#endif

	// get the TPM object
	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetTpmObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTPMPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Set Secret
	result = Tspi_Policy_SetSecret(hTPMPolicy, TESTSUITE_OWNER_SECRET_MODE,
				       TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}


		// create a new Policy
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
					TSS_POLICY_USAGE, &hNewPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetPolicy ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Set the new policy's Secret
	result = Tspi_Policy_SetSecret(hNewPolicy, TESTSUITE_NEW_SECRET_MODE,
				       TESTSUITE_NEW_SECRET_LEN, TESTSUITE_NEW_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Call Change Auth
	result = Tspi_ChangeAuth(hSRK, hTPM, hNewPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_ChangeAuth", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	/* Success, the SRK now has auth.  Set the authdatausage bit in the SW key to 1 */
	usageauth = TRUE;
	result = Tspi_SetAttribUint32(hSRK, TSS_TSPATTRIB_KEY_INFO,
				      TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE, usageauth);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_SetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Context_UnregisterKey(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hPsSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_UnregisterKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Context_RegisterKey(hContext, hSRK, TSS_PS_TYPE_SYSTEM, SRK_UUID,
					  TSS_PS_TYPE_SYSTEM, NULL_UUID);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_RegisterKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Context_CloseObject(hContext, hPsSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CloseObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Context_CloseObject(hContext, hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CloseObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	/* Now reload the SRK and make sure its authdatausage bit is TRUE */
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID for hSRK", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_GetAttribUint32(hSRK, TSS_TSPATTRIB_KEY_INFO,
				      TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE, &usageauth);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	if (usageauth) {
		result = TSS_SUCCESS;
		print_success(nameOfFunction, result);
	} else {
		result = TSS_E_FAIL;
		print_verifystr("SRK's authdatausage was correct", "TRUE", "FALSE");
	}

	Tspi_Context_Close(hContext);
	exit(result);
}
