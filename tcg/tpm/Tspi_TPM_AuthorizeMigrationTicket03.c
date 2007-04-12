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
 *	Tspi_TPM_AuthorizeMigrationTicket03.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_TPM_AuthorizeMigrationTicket
 *	The purpose of this test case is to get TSS_E_INVALID_HANDLE
 *		to be returned. This is easily accomplished by passing in 
 *		an invalid first parameter. 
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		GetTPMObject
 *		Create Object
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

main_v1_1(void){

	char		*nameOfFunction = "Tspi_TPM_AuthorizeMigrationTicket03";
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_HTPM	hTPM;
	UINT32		TargetPubKeyLength;
	BYTE*		TargetPublicKeyData;
	TSS_HKEY	hTargetPubKey;
	BYTE*		MigTicket;
	UINT32		TicketLength;

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
		//Create Object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
				TSS_KEY_SIZE_2048 | TSS_KEY_TYPE_STORAGE
				| TSS_KEY_MIGRATABLE, &hTargetPubKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Call To Authorize Migration Ticket
	result = Tspi_TPM_AuthorizeMigrationTicket(-1, 
			hTargetPubKey, TSS_MS_REWRAP,
			&TicketLength, &MigTicket); 
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_HANDLE) {
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, hTargetPubKey);
			Tspi_Context_Close(hContext);
			exit(result);
		}
		else{
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_CloseObject(hContext, hTargetPubKey);
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}
	else{
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_CloseObject(hContext, hTargetPubKey);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
