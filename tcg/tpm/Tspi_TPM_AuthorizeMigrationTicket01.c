/*
 *
 *   Copyright (C) International Business Machines  Corp., 2004
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
 *	Tspi_TPM_AuthorizeMigrationTicket01.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_TPM_AuthorizeMigrationTicket
 *	The purpose of this test case is to get TSS_SUCCESS to be
 *		returned. This is easily accomplished by following 
 *		the algorithm described below.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		GetTPMObject
 *		Load SRK
 *		Get Policy Object
 *		Set Secret
 *		Create Object
 *		Get Policy Object
 *		Set Secret
 *		Create Key
 *		Load Key
 *		Get PubKey
 *		Set AttribData
 *
 *	Test:	Call AuthorizeMigrationTicket. If this is unsuccessful check for 
 *		type of error, and make sure it returns the proper return code
 * 
 *	Cleanup:
 *		Free memory associated with the context
 *		Close hTargetPubKey object
 *		Close Context
 *		Print error/success message.
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1
 *
 * HISTORY
 *	Author:	Kathy Robertson
 *	Date:	June 2004
 *	Email:	klrobert@us.ibm.com
 *
 * RESTRICTIONS
 *	None.
 */
#include <tss/tss.h>
#include "../common/common.h"


extern int commonErrors(TSS_RESULT result);
extern TSS_UUID SRK_UUID;

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

	char		*nameOfFunction = "Tspi_TPM_AuthorizeMigrationTicket01";
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_HTPM	hTPM;
	TSS_HKEY	hSRK;
	UINT32		TargetPubKeyLength;
	BYTE*		TargetPublicKeyData;
	TSS_HKEY	hTargetPubKey;
	BYTE*		MigTicket;
	UINT32		TicketLength;
	TSS_HPOLICY	srkUsagePolicy, keyUsagePolicy;

	print_begin_test(nameOfFunction);

		//Create Result
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
		//Connect Result
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get TPM Object
	result = Tspi_Context_GetTpmObject(hContext,  &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetTPMObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
						SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE,
					&srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Policy_SetSecret(srkUsagePolicy, TSS_SECRET_MODE_PLAIN,
					0, NULL);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Create Object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
				TSS_KEY_SIZE_2048 | TSS_KEY_TYPE_SIGNING |
				TSS_KEY_MIGRATABLE |
				TSS_KEY_NO_AUTHORIZATION,
				&hTargetPubKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE,
					&keyUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hTargetPubKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret
	result = Tspi_Policy_SetSecret(keyUsagePolicy,
				TSS_SECRET_MODE_PLAIN,
				20, TSS_WELL_KNOWN_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hTargetPubKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Key_CreateKey(hTargetPubKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Key_LoadKey(hTargetPubKey, hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get Public Key
	result = Tspi_Key_GetPubKey(hTargetPubKey, 
				&TargetPubKeyLength, 
				&TargetPublicKeyData);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_GetPubKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hTargetPubKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set AttribData
	result = Tspi_SetAttribData(hTargetPubKey, 
				TSS_TSPATTRIB_KEY_BLOB, 
				TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
				TargetPubKeyLength,
				TargetPublicKeyData);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_SetAttribData ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hTargetPubKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Call To Authorize Migration Ticket
	result = Tspi_TPM_AuthorizeMigrationTicket(hTPM, 
			hTargetPubKey, TSS_MS_REWRAP,
			&TicketLength, &MigTicket); 
	if (result != TSS_SUCCESS) {
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, hTargetPubKey);
			Tspi_Context_Close(hContext);
			exit(1);
		}
		else{
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, hTargetPubKey);
			Tspi_Context_Close(hContext);
			exit(1);
		}
	}
	else{
		print_error(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_CloseObject(hContext, hTargetPubKey);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
