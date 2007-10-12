/*
 *
 *   Copyright (C) International Business Machines  Corp., 2004, 2005, 2007
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
 *	Tspi_Key_UnloadKey.c
 *
 * DESCRIPTION
 *	This test will verify that
 *		- A loaded key will encrypt/decrypt data correctly.
 *		- When key is unloaded, decrypt will fail
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Create Key Objects
 *		Create Enc Data
 *		Load Key By UUID (hSRK)
 *		Load Key (hKey)
 *
 *	Test:
 *		Call Data_Bind and Data_Unbind
 *		Compare Unbound data to original data (Should match)
 *		Unload Key
 *		Call Data_Bind
 *		Call Data_Unbind (Should fail)
 *		Load Key then call Data_Unbind again
 *		Comare Unbound data to original data (Should match)
 *
 *	Cleanup:
 *		Free memory related to hContext
 *		Close context
 *
 * USAGE
 *      First parameter is --options
 *                         -v or --version
 *      Second parameter is the version of the test case to be run
 *      This test case is currently only implemented for v1.1
 *
 * HISTORY
 *	5/2007	loulwa@us.ibm.com	Originated
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include "common.h"


int
main(int argc, char **argv)
{
	char		version;

	version = parseArgs(argc, argv);
	if (version)
		main_v1_1();
	else
		print_wrongVersion();
}

int
main_v1_1(void)
{
	char		*function = "Tspi_Key_UnloadKey";
	TSS_HCONTEXT	hContext;
	TSS_HKEY	hSRK;
	TSS_HKEY	hKey;
	TSS_HPOLICY	phPolicy;
	BYTE		*prgbUnboundData;
	BYTE		rgbDataToBind[32] = {0,1,3,4,5,6,7,0,1,2,3,4,5,6,7,
					     0,1,2,3,4,5,6,7,0,1,2,3,4,5,6,7};
	TSS_HENCDATA	hEncData;
	UINT32		pulUnboundDataLength;
	UINT32		ulDataLength = 32;
	TSS_RESULT	result;

	print_begin_test(function);

		// Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Context_Create", result);
		exit(result);
	}

		// Connect to Context
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Context_Connect", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Load SRK Key By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
						SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Context_LoadKeyByUUID (hSRK)", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

#ifndef TESTSUITE_NOAUTH_SRK
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &phPolicy);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_GetPolicyObject(phPolicy)", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Policy_SetSecret(phPolicy, TESTSUITE_SRK_SECRET_MODE, 
					TESTSUITE_SRK_SECRET_LEN, 
					TESTSUITE_SRK_SECRET);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Policy_SetSecret(phPolicy)", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
#endif

		// create hKey & load it
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
					    TSS_KEY_TYPE_BIND, &hKey);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Context_CreateObject (hKey)", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_CreateKey(hKey, hSRK, 0);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Key_CreateKey", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_LoadKey(hKey, hSRK);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Key_LoadKey", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		
		// Create data object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA,
					    TSS_ENCDATA_BIND, &hEncData);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Context_CreateObject (hEncData)", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Data Bind
	result = Tspi_Data_Bind(hEncData, hKey, ulDataLength, rgbDataToBind);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Data_Bind (hEncData, hKey)", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Data Unbind
	result = Tspi_Data_Unbind(hEncData, hKey, &pulUnboundDataLength,
				  &prgbUnboundData);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Data_Unbind (hEncData, hKey)", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Compare prgbUnboundData to rgbDataToBind (Should match)
	if ((pulUnboundDataLength != ulDataLength) || (memcmp(prgbUnboundData, 
		rgbDataToBind, pulUnboundDataLength) != 0))
	{
		print_error("Data not matching", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Unload key
	result = Tspi_Key_UnloadKey(hKey);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Key_UnloadKey (hKey)", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Data Bind
	result = Tspi_Data_Bind(hEncData, hKey, ulDataLength, rgbDataToBind);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Data_Bind (hEncData, hKey)", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Data Unbind - should fail
	result = Tspi_Data_Unbind(hEncData, hKey, &pulUnboundDataLength,
				  &prgbUnboundData);
	if (TSS_ERROR_CODE(result) != TCS_E_INVALID_KEY)
	{
		print_error("Tspi_Data_Unbind (hEncData, hKey)", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Load key again
	result = Tspi_Key_LoadKey(hKey, hSRK);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Key_LoadKey", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// Data Unbind - should succeed now
	result = Tspi_Data_Unbind(hEncData, hKey, &pulUnboundDataLength,
				  &prgbUnboundData);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_DataUnbind", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		// compare again (should match)
	if ((pulUnboundDataLength == ulDataLength) && 
		!memcmp(prgbUnboundData, rgbDataToBind, pulUnboundDataLength))
	{
		print_success(function, result);
		print_end_test(function);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(0);
	} else {
		printf("%s: unbound Data doesn't match original data.\n", function);
	}

	print_end_test(function);
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_Close(hContext);
	exit(TSS_E_FAIL);
}
