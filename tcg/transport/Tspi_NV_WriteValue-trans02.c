/*
 * The Initial Developer of the Original Code is Intel Corporation. 
 * Portions created by Intel Corporation are Copyright (C) 2007 Intel Corporation. 
 * All Rights Reserved.
 *
 * This program is free software;  you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY;  without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 * the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program;  if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 * NAME
 *	Tspi_nv_WriteValue01.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_NV_WriteValue without password
 *	The index require the authwrite
 *	The purpose of this test case is to get TPM_AUTH_CONFLICT to be returned.
 *	If nv Unlocked, return TSS_SUCCESS
 *	To have it return success, you need to follow the
 *	algorithm described below.
 *
 * ALGORITHM
 *	Setup:
 *		Tspi_Context_Create
 *		Tspi_Context_Connect
 *		Tspi_Context_CreateObject(NV object)
 *		If nv locked, Setsecret to TPM policy with correct owner passwd
 *		CreatPolicy, Setsecret and assign to the policy
 *		Tspi_SetAttribUint32(Index, permission, datasize)
 *		(The Index is 0x00011131)
 *		(The Permission is 0x4)
 *		(The datasize is 0xa)
 *		Tspi_NV_DefineSpace      
 *		Tspi_Context_Create
 *		Tspi_Context_Connect
 *		Tspi_Context_CreateObject(NV object)
 *		Tspi_SetAttribUint32(Index, permission, datasize)
 *		(The Index is 0x00011131)
 *		Tspi_NV_WriteValue 
 *
 *	Test:	
 *		Call Tspi_NV_WriteValue. If it is not a success
 *		Make sure that it returns the proper return codes
 *
 *	Cleanup:
 *		Free memory associated with the context
 *		Close context
 *		Print error/success message
 *
 * USAGE:	
 *	First parameter is --options
 *	-v or --version
 *	Second Parameter is the version of the test case to be run.
 *	This test case is currently implemented for 1.2
 *
 * HISTORY
 *	Author:	Jacfee,Liu
 *	Date:	Apr 2007
 *	Email:	bigbigfei@gmail.com
 *
 * RESTRICTIONS
 *	None.
 */

#include "common.h"

int
main( int argc, char **argv )
{
	char	version;

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
	char	     *nameOfFunction    = "Tspi_nv_WriteValue-trans02";
	
	TSS_HCONTEXT hContext           = NULL_HCONTEXT;
	TSS_HNVSTORE hNVStore           = 0;//NULL_HNVSTORE
	TSS_HOBJECT  hPolObject         = NULL_HOBJECT;
	TSS_HPOLICY  hPolicy            = NULL_HPOLICY;
	TSS_HTPM     hTPM               = NULL_HTPM;
      	BYTE         *auth              = "123456";
	UINT32       auth_length        = 6;
	BYTE         *data              = "1234567890";
	TSS_RESULT   result;
	TSS_HKEY     hSigningKey, hWrappingKey, hSRK;

	print_begin_test(nameOfFunction);

	result = connect_load_all(&hContext, &hSRK, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		exit(result);
	}

	result = Testsuite_Transport_Init(hContext, hSRK, hTPM, TRUE, TRUE, &hWrappingKey,
					  &hSigningKey);
	if (result != TSS_SUCCESS) {
		print_error("Testsuite_Transport_Init", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	/* Create TPM NV object */
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0,&hNVStore);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		/* Create policy object for the NV object*/
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &hPolObject);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		/* Set password */
	result = Tspi_Policy_SetSecret(hPolObject, TSS_SECRET_MODE_PLAIN, auth_length, auth);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Policy_SetSecret", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		/* Set password */
	result = Tspi_Policy_AssignToObject(hPolObject, hNVStore);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Policy_AssignToObject", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	/* Set the index to be defined. */
	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0,0x00011131);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_SetAttribUint32 for setting NV index", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}


	/* Set the permission for the index. */
	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_PERMISSIONS, 0, 0x4);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_SetAttribUint32 for setting permission", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);	
       }


	/* Set the data size to be defined. */
	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_DATASIZE, 0, 0xa);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_SetAttribUint32 for setting data size", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
     	}

	/*Define NV space*/
	result = Tspi_NV_DefineSpace(hNVStore, 0, 0);

		//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		exit(result);
	}
		//Connect Context
	result = Tspi_Context_Connect(hContext,NULL);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		Tspi_Context_FreeMemory(hContext, NULL);   
		Tspi_Context_Close(hContext);
		exit(result);
	}

	    	/* Create TPM NV object */
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_NV, 0,&hNVStore);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}


	/* Set the index to be defined. */
	result = Tspi_SetAttribUint32(hNVStore, TSS_TSPATTRIB_NV_INDEX, 0,0x00011131);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_SetAttribUint32 for setting NV index", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_NV_WriteValue(hNVStore, /*offset*/0,/*datalength*/10, data);  

#ifdef CLEAR_TEST_INDEX
	Tspi_Context_GetTpmObject(hContext, &hTPM);
	Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hPolicy);
	Tspi_Policy_SetSecret(hPolicy, TESTSUITE_OWNER_SECRET_MODE,
			TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);
	Tspi_NV_ReleaseSpace(hNVStore);
#endif

#ifdef NV_LOCKED
       if (TSS_ERROR_CODE(result)== TPM_E_AUTH_CONFLICT)
#else
       if (TSS_ERROR_CODE(result)== TSS_SUCCESS)
#endif
	{
		print_error("Tspi_NV_WriteValue", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

       result = Testsuite_Transport_Final(hContext, hSigningKey);
       if (TSS_ERROR_CODE(result)== TSS_SUCCESS)
       {
	       print_success(nameOfFunction, result);
	       print_end_test(nameOfFunction);
	       Tspi_Context_FreeMemory(hContext, NULL);
	       Tspi_Context_Close(hContext);
	       exit(0);
       } else {
	       print_error(nameOfFunction, result);
	       print_end_test(nameOfFunction);
	       Tspi_Context_FreeMemory(hContext, NULL);
	       Tspi_Context_Close(hContext);
	       if ( result == TSS_SUCCESS )
		       exit(-1);
	       exit(result);
       }
}
