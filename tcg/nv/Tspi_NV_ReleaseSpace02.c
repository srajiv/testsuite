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
 *	Tspi_Nv_ReleaseSpace02.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_NV_ReleaseSpace with Owner password
 *	With -1 as the nvstore
 *	The purpose of this test case is to get TSS_E_INVALID_HANDLE to be returned.
 *	To have it return success, you need to follow the
 *	algorithm described below.
 *
 * ALGORITHM
 *	Setup:
 *		Tspi_Context_Create
 *		Tspi_Context_Connect
 *		Setsecret to TPM policy with the correct owner passwd
 *		Tspi_NV_ReleaseSpace(-1)
 *     
 *	Test:	
 *		Call Tspi_NV_ReleaseSpace. If it is not a success
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
	char	     *nameOfFunction    = "Tspi_Nv_ReleaseSpace02";
	
	TSS_HCONTEXT hContext           = NULL_HCONTEXT;
	TSS_HPOLICY  hPolicy            = NULL_HPOLICY;
	TSS_HTPM     hTPM               = NULL_HTPM;
	TSS_RESULT   result;
 
	print_begin_test(nameOfFunction);

		//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
		//Connect Context
	result = Tspi_Context_Connect(hContext,NULL);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);  
		Tspi_Context_Close(hContext);
		exit(result);
	}

		/* Get TPM object */
	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Context_GetTpmObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hPolicy);
	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		/* Set password */
	result = Tspi_Policy_SetSecret(hPolicy, TESTSUITE_OWNER_SECRET_MODE,
					TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);

	if (result != TSS_SUCCESS)
	{
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

      /*Release NV space*/
	result = Tspi_NV_ReleaseSpace(-1);

#ifdef NV_LOCKED	
       if (TSS_ERROR_CODE(result)== TSS_E_INVALID_HANDLE)
       {              
        	print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(0);
       }
       else{
		print_error("Tspi_NV_ReleaseSpace", result);
	  	print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		if ( result == TSS_SUCCESS )
			exit(-1);
		exit(result);
     	}

#else
       if (TSS_ERROR_CODE(result)== TSS_E_INVALID_HANDLE)
       {
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(0);
       }
       else{
		print_error("Tspi_NV_ReleaseSpace", result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		if ( result == TSS_SUCCESS )
			exit(-1);
		exit(result);
     	}
#endif
}
