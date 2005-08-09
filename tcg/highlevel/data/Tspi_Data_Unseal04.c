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
 *	Tspi_Data_Seal04.c
 *
 * DESCRIPTION
 *	This test will verify Seal and Unseal.
 *      Data is smaller than the RSA key's size.
 *	The goal of this test is to verify that
 *	the unsealed data matches the original data.
 *	In this case hPcrComposite object not set (NULL).
 *
 *
 * ALGORITHM
 *	Setup:
 *              Create Context
 *              Connect Context
 *              Create RSAKEY Object
 *              Load Key By UUID for SRK
 *              GetPolicy
 *              SetSecret
 *              Create Key
 *              Load Key
 *              Create Seal Data Object
 *
 *	Test:	
 *              Seal Data (data smaller than RSA key size)
 *              Unseal Data
 *              Check that Data returned matches original data
 *		
 *	Cleanup:
 *		Free memory associated with the context
 *		Close hKey object
 *              Close Encrypted Data Object
 *		Close context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1
 *
 * HISTORY
 *	Author:	Debora Velarde
 *	Date:	09/2004
 *	Email:	dvelarde@us.ibm.com
 *
 * RESTRICTIONS
 *	None.
 */

#include <trousers/tss.h>
#include "common.h"



int main(int argc, char **argv)
{
	char		*version;

	version = parseArgs( argc, argv );
		// if it is not version 1.1, print error
	if(strcmp(version, "1.1")){
		print_wrongVersion();
	}
	else{
		main_v1_1();
	}
}

main_v1_1(void){

	char		*nameOfFunction = "Tspi_Data_Seal04";
	TSS_FLAG	initFlags;
	TSS_HKEY	hKey;
	TSS_HKEY	hSRK;
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_RESULT	result;
	initFlags	= TSS_KEY_TYPE_STORAGE | TSS_KEY_SIZE_2048  |
			TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
			TSS_KEY_NOT_MIGRATABLE;
	TSS_HENCDATA	hEncData;
	TSS_HKEY	hEncKey;
	TSS_HPOLICY	phPolicy;
	UINT32		dataLength=32;  //32 bytes = 256 bits
	UINT32		dataUnsealedLength=0;
	BYTE*		rgbDataToSeal;
	BYTE*		rgbDataUnsealed; 
	int		exitCode=0;

	print_begin_test(nameOfFunction);

	rgbDataToSeal = malloc(dataLength);
	rgbDataToSeal = "0123456789ABCDEF0123456789ABCDEF";
	//print_success(rgbDataToSeal, 0);

		//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
	print_success("Create Context", result);

		//Connect Context
	result = Tspi_Context_Connect(hContext, NULL);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	print_success("Connect Context", result);

		//Create Object
	result = Tspi_Context_CreateObject(hContext, 
				TSS_OBJECT_TYPE_RSAKEY,
				initFlags, &hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	print_success("Create RSAKEY Object", result); 

		//Load Key by UUID for SRK
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, 
				SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	print_success("Load Key UUID for SRK", result);


                //GetPolicyObject
        result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &phPolicy);
        if (result != TSS_SUCCESS) {
                print_error("Tspi_GetPolicyObject", result);
                print_error_exit(nameOfFunction, err_string(result));
                Tspi_Context_CloseObject(hContext, hKey);
                Tspi_Context_Close(hContext);
                exit(result);
        }
        print_success("Get Policy Object", result);


                //SetSecret
        result = Tspi_Policy_SetSecret(phPolicy, TSS_SECRET_MODE_PLAIN, 0, NULL);
        if (result != TSS_SUCCESS) {
                print_error("Tspi_Policy_SetSecret", result);
                print_error_exit(nameOfFunction, err_string(result));
                Tspi_Context_CloseObject(hContext, hKey);
                Tspi_Context_Close(hContext);
                exit(result);
        }
        print_success("Policy Set Secret", result);

                //CreateKey
        result = Tspi_Key_CreateKey(hKey, hSRK, 0);
        if (result != TSS_SUCCESS) {
                print_error("Tspi_Key_CreateKey", result);
                print_error_exit(nameOfFunction, err_string(result));
                Tspi_Context_CloseObject(hContext, hKey);
                Tspi_Context_Close(hContext);
                exit(result);
        }
        print_success("Key CreateKey", result);

                //LoadKey
        result = Tspi_Key_LoadKey(hKey, hSRK);
        if (result != TSS_SUCCESS) {
                print_error("Tspi_Key_LoadKey", result);
                print_error_exit(nameOfFunction, err_string(result));
                Tspi_Context_CloseObject(hContext, hKey);
                Tspi_Context_Close(hContext);
                exit(result);
        }
        print_success("Key LoadKey", result);


               //Create Encrypted Data Object
        result = Tspi_Context_CreateObject(hContext,
                                TSS_OBJECT_TYPE_ENCDATA,
                                TSS_ENCDATA_SEAL,
                                &hEncData);
        if (result != TSS_SUCCESS) {
                print_error("Tspi_Context_CreateObject", result);
                print_error_exit(nameOfFunction, err_string(result));
                Tspi_Context_FreeMemory(hContext, NULL);
                Tspi_Context_Close(hContext);
                exit(result);
        }
        print_success("Create Encrypted Data Object", result);


	//Seal data
	//result = Tspi_Data_Seal(hEncData, hEncKey, dataLength, rgbDataToSeal, hPcrComposite );
	result = Tspi_Data_Seal(hEncData, 
				hKey, 
				dataLength, 
				rgbDataToSeal, NULL_HPCRS);
	if (result != TSS_SUCCESS) {
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_CloseObject(hContext, hEncData);
			Tspi_Context_Close(hContext);
			exit(1);
	}
	else {
		print_success("Tspi_Data_Seal", result);
		exitCode = 0;
	}

	//Unseal data
	result = Tspi_Data_Unseal(hEncData, 
				hKey,
				&dataUnsealedLength,
				&rgbDataUnsealed );
	if (result != TSS_SUCCESS) {
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_CloseObject(hContext, hEncData);
			Tspi_Context_Close(hContext);
			exit(1);
	}
	else {
		print_success("Tspi_Data_Unseal", result);
		exitCode = 0;
	}
	
	
	//compare Original Data with Data returned by Unseal
	//First compare size
	if (dataLength == dataUnsealedLength)
	{
	  //Size correct, check if data matches
	  print_success("Unseal data length matches length of original data", result);
	  if (strcmp(rgbDataToSeal, rgbDataUnsealed) == 0)
	  {
	    	//strings match
	    	print_success("Unseal data matches original data!", result);
		exitCode = 0;
	  }
	  else {
	     	//string size the same but strings don't match
		print_error("Unseal data does NOT match original data", result);
		exitCode = 1;
	  }
	}
	else {
  		//string sizes do not match, so strings do not match
		print_error("Unseal data size does NOT match original data size", result);
		exitCode = 1;
	}
	
	print_end_test(nameOfFunction);
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_CloseObject(hContext, hKey);
	Tspi_Context_CloseObject(hContext, hEncData);
	Tspi_Context_Close(hContext);
	exit(exitCode);

}
