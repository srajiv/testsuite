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
 *	Tspi_Callbacks01.c
 *
 * DESCRIPTION
 *	This test will verify the correct operation of TSS 1.2 style
 *	callbacks.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect
 *		Create Object
 *		Load Key By UUID for SRK
 *
 *	Test:
 *
 *	Cleanup:
 *		Free memory associated with the context
 *		Close context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1
 *
 * HISTORY
 *	Kent Yoder, kyoder@users.sf.net
 *
 * RESTRICTIONS
 *	None.
 */

#include "common.h"



int main(int argc, char **argv)
{
	char version;

	version = parseArgs( argc, argv );
	if (version == TESTSUITE_TEST_TSS_1_2)
		main_v1_2(version);
	else if (version == TESTSUITE_TEST_TSS_1_1)
		main_v1_1();
	else
		print_wrongVersion();
}

main_v1_1()
{
	char		*nameOfFunction = "Tspi_Callbacks01";
	TSS_FLAG	initFlags;
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_HKEY	hSRK;
	TSS_HTPM	hTPM;
	TSS_HPOLICY	hSRKPolicy;
	UINT32		tmp, i;
	UINT32		policyAttrib[4], tpmAttrib[2];
	TSS_FLAG	policyAttribFlag[4], policySubFlag[4];
	TSS_FLAG	tpmAttribFlag[2], tpmSubFlag[2];

	/* initialize the callback pointers and flags */
	policyAttrib[0] = 0xff000000;
	policyAttrib[1] = 0x00ff0000;
	policyAttrib[2] = 0x0000ff00;
	policyAttrib[3] = 0x000000ff;
	tpmAttrib[0] = 0xf0000ff0;
	tpmAttrib[1] = 0x00ff000f;

	policySubFlag[0] = 0x000000ff;
	policySubFlag[1] = 0x0000ff00;
	policySubFlag[2] = 0x00ff0000;
	policySubFlag[3] = 0xff000000;
	tpmSubFlag[0] = 0xf000000f;
	tpmSubFlag[1] = 0x00f00f00;

	policyAttribFlag[0] = TSS_TSPATTRIB_POLICY_CALLBACK_HMAC;
	policyAttribFlag[1] = TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC;
	policyAttribFlag[2] = TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP;
	policyAttribFlag[3] = TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM;
	tpmAttribFlag[0] = TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY;
	tpmAttribFlag[1] = TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY;

	print_begin_test(nameOfFunction);

		//Create Context and connect
	result = connect_load_all(&hContext, &hSRK, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("connect_load_srk", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}

	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE,
				      &hSRKPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	/* set all callbacks */
	for (i = 0; i < 4; i++) {
		result = Tspi_SetAttribUint32(hSRKPolicy,
					      policyAttribFlag[i],
					      policySubFlag[i],
					      policyAttrib[i]);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_SetAttribUint32", result);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}

	for (i = 0; i < 2; i++) {
		result = Tspi_SetAttribUint32(hTPM,
					      tpmAttribFlag[i],
					      tpmSubFlag[i],
					      tpmAttrib[i]);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_SetAttribUint32", result);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}

	/* check all callbacks */
	for (i = 0; i < 4; i++) {
		tmp = 0;
		result = Tspi_GetAttribUint32(hSRKPolicy,
					      policyAttribFlag[i],
					      policySubFlag[i],
					      &tmp);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_SetAttribUint32", result);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}

		if (tmp != policyAttrib[i]) {
			print_verifyerr("policy callback address", policyAttrib[i], tmp);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}

	for (i = 0; i < 2; i++) {
		result = Tspi_GetAttribUint32(hTPM,
					      tpmAttribFlag[i],
					      tpmSubFlag[i],
					      &tmp);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_SetAttribUint32", result);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}

		if (tmp != tpmAttrib[i]) {
			print_verifyerr("tpm callback address", policyAttrib[i], tmp);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}


	print_success(nameOfFunction, result);
	print_end_test(nameOfFunction);
	Tspi_Context_Close(hContext);
	exit(0);
}

int
verify_callback(TSS_CALLBACK *c1, TSS_CALLBACK *c2)
{
	if (c1->callback != c2->callback) {
		print_verifyerr("callback address", c1->callback, c2->callback);
		return 1;
	}

	if (c1->appData != c2->appData) {
		print_verifyerr("callback app data", c1->appData, c2->appData);
		return 1;
	}

	if (c1->alg != c2->alg) {
		print_verifyerr("callback algorithm", c1->alg, c2->alg);
		return 1;
	}

	return 0;
}

main_v1_2(char version)
{
	char		*nameOfFunction = "Tspi_Callbacks01";
	TSS_FLAG	initFlags;
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_HKEY	hSRK;
	TSS_HTPM	hTPM;
	TSS_HPOLICY	hSRKPolicy;
	UINT32		size, i;
	TSS_FLAG	policyAttribFlag[4], tpmAttribFlag[2];
	TSS_CALLBACK	policy_cb[4], tpm_cb[2], *cb_ptr;
	BYTE		*data;

	/* initialize the callback pointers and flags */
	policy_cb[0].callback = (PVOID)0xff000000;
	policy_cb[0].appData = (PVOID)0x000000ff;
	policy_cb[0].alg = 0x00ffff00;
	policy_cb[1].callback = (PVOID)0x00ff0000;
	policy_cb[1].appData = (PVOID)0x0000ff00;
	policy_cb[1].alg = 0x00ffffff;
	policy_cb[2].callback = (PVOID)0x0000ff00;
	policy_cb[2].appData = (PVOID)0x00ff0000;
	policy_cb[2].alg = 0x0000ffff;
	policy_cb[3].callback = (PVOID)0x000000ff;
	policy_cb[3].appData = (PVOID)0xff0000ff;
	policy_cb[3].alg = 0xffff0000;

	tpm_cb[0].callback = (PVOID)0xf000000f;
	tpm_cb[0].appData = (PVOID)0xff0000ff;
	tpm_cb[0].alg = 0x00ffff00;
	tpm_cb[1].callback = (PVOID)0xff00ff00;
	tpm_cb[1].appData = (PVOID)0xffff00ff;
	tpm_cb[1].alg = 0xffff00ff;

	policyAttribFlag[0] = TSS_TSPATTRIB_POLICY_CALLBACK_HMAC;
	policyAttribFlag[1] = TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC;
	policyAttribFlag[2] = TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP;
	policyAttribFlag[3] = TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM;
	tpmAttribFlag[0] = TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY;
	tpmAttribFlag[1] = TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY;

	print_begin_test(nameOfFunction);

		//Create Context and connect
	result = connect_load_all(&hContext, &hSRK, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("connect_load_srk", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}

	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE,
				      &hSRKPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	/* set all callbacks */
	for (i = 0; i < 4; i++) {
		result = Tspi_SetAttribData(hSRKPolicy,
					    policyAttribFlag[i],
					    0, sizeof(TSS_CALLBACK),
					    (BYTE *)&policy_cb[i]);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_SetAttribData", result);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}

	for (i = 0; i < 2; i++) {
		result = Tspi_SetAttribData(hTPM,
					    tpmAttribFlag[i],
					    0, sizeof(TSS_CALLBACK),
					    (BYTE *)&tpm_cb[i]);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_SetAttribData", result);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}

	/* check all callbacks */
	for (i = 0; i < 4; i++) {
		result = Tspi_GetAttribData(hSRKPolicy,
					    policyAttribFlag[i],
					    0, &size, &data);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_GetAttribData", result);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}

		if (size != sizeof(TSS_CALLBACK)) {
			print_verifyerr("policy callback size", sizeof(TSS_CALLBACK),
					size);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}

		cb_ptr = (TSS_CALLBACK *)data;
		if (verify_callback(&policy_cb[i], cb_ptr)) {
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}

		result = Tspi_Context_FreeMemory(hContext, data);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Context_FreeMemory", result);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}

	for (i = 0; i < 2; i++) {
		result = Tspi_GetAttribData(hTPM,
					    tpmAttribFlag[i],
					    0, &size, &data);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_GetAttribData", result);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}

		if (size != sizeof(TSS_CALLBACK)) {
			print_verifyerr("tpm callback size", sizeof(TSS_CALLBACK),
					size);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}

		cb_ptr = (TSS_CALLBACK *)data;
		if (verify_callback(&tpm_cb[i], cb_ptr)) {
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}

		result = Tspi_Context_FreeMemory(hContext, data);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Context_FreeMemory", result);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}


	print_success(nameOfFunction, result);
	print_end_test(nameOfFunction);
	Tspi_Context_Close(hContext);
	exit(0);
}
