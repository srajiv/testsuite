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
 *	Tspi_Context_CloseSignTransport03
 *
 * DESCRIPTION
 *	This test will verify Tspi_Context_CloseSignTransport.
 *	The purpose of this test case is to get an error code to be returned.
 *		This is done by following the algorithm described below.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Create key object for transport wrapping key
 *		Create key object for testing key
 *		Create transport wrapping key
 *		Create testing key
 *		Load transport wrapping key
 *		Open a transport session
 *		Load testing key
 *		Execute a wrapped command
 *
 *	Test:	Call Tspi_Context_CloseSignTransport
 *		Make sure that it returns the proper return codes
 *
 *	Cleanup:
 *		Close context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1 and 1.2
 *
 *
 * HISTORY
 *	Author:	Giampaolo Libralao
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdlib.h>

#include "common.h"


int main(int argc, char **argv)
{
	char		version;

	version = parseArgs( argc, argv );
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
	char		*nameOfFunction = "Tspi_Context_CloseSignTransport03";
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_HKEY        hSRK, hWrappingKey, hSigningKey;
	TSS_HPOLICY     srkUsagePolicy, hTPMPolicy, hPolicy;
	UINT32		pubSRKLen;
	BYTE*		pubSRK;
	TSS_HTPM	hTPM;

	print_begin_test(nameOfFunction);

		//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}

	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

                //Load Key By UUID
        result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK );
        if ( result != TSS_SUCCESS )
        {
                print_error( "Tspi_Context_LoadKeyByUUID (hSRK)", result );
                print_error_exit( nameOfFunction, err_string(result) );
                Tspi_Context_FreeMemory( hContext, NULL );
                Tspi_Context_Close( hContext );
                exit( result );
        }

#ifndef TESTSUITE_NOAUTH_SRK
                //Get Policy Object
        result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);
        if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	//Set Secret
	result = Tspi_Policy_SetSecret(srkUsagePolicy, TESTSUITE_SRK_SECRET_MODE,
					TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET);
	if ( result != TSS_SUCCESS )
	{
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
#endif

	result = Tspi_Context_GetTpmObject( hContext, &hTPM );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_GetTpmObject", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_GetPolicyObject( hTPM, TSS_POLICY_USAGE, &hTPMPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Policy_SetSecret( hTPMPolicy, TESTSUITE_OWNER_SECRET_MODE,
					TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

#if 1
#warning Change these calls to Tspi_TPM_GetSRKPub when it exists
	result = Tspi_TPM_SetStatus( hTPM, TSS_TPMSTATUS_DISABLEPUBSRKREAD, FALSE );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_TPM_SetStatus", result );
		print_error_exit( nameOfFunction, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Key_GetPubKey(hSRK, &pubSRKLen, &pubSRK);
	if ( result != TSS_SUCCESS )
	{
		print_error("Tspi_Key_GetPubKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
#endif
	result = Tspi_Context_FreeMemory(hContext, pubSRK);
	if ( result != TSS_SUCCESS )
	{
		print_error("Tspi_Context_FreeMemory", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
					   TSS_KEY_SIZE_512 | TSS_KEY_TYPE_LEGACY |
					   TSS_KEY_AUTHORIZATION, &hWrappingKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
					   TSS_POLICY_USAGE, &hPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Policy_SetSecret(hPolicy, TESTSUITE_KEY_SECRET_MODE,
					TESTSUITE_KEY_SECRET_LEN, TESTSUITE_KEY_SECRET);
	if ( result != TSS_SUCCESS )
	{
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Policy_AssignToObject(hPolicy, hWrappingKey);
	if ( result != TSS_SUCCESS )
	{
		print_error("Tspi_Policy_AssignToObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_CreateKey(hWrappingKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_LoadKey(hWrappingKey, hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_LoadKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
					   TSS_KEY_SIZE_512 | TSS_KEY_TYPE_SIGNING |
					   TSS_KEY_NO_AUTHORIZATION, &hSigningKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		/* delay loading the signing key so that it can be our transported command */

	result = Tspi_Context_SetTransEncryptionKey(hContext, hWrappingKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	/* enable the transport session */
	result = Tspi_SetAttribUint32(hContext, TSS_TSPATTRIB_CONTEXT_TRANSPORT,
				      TSS_TSPATTRIB_CONTEXTTRANS_CONTROL,
				      TSS_TSPATTRIB_ENABLE_TRANSPORT);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_SetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	/* Turn logging on. Skipping this step would give us TPM_BAD_MODE when we try to close
	 * the session. */
	result = Tspi_SetAttribUint32(hContext, TSS_TSPATTRIB_CONTEXT_TRANSPORT,
				      TSS_TSPATTRIB_CONTEXTTRANS_MODE,
				      TSS_TSPATTRIB_TRANSPORT_AUTHENTIC_CHANNEL);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_SetAttribUint32", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	
	result = Tspi_Context_CloseSignTransport(hContext, 0xffffffff, NULL);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_HANDLE) {
		if (!checkNonAPI(result)) {
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(result);
		} else {
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(result);
		}
	} else {
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
