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
 *	Tspi_Key_ConvertMigrationBlob-trans02.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_Key_ConvertMigrationBlob executes successfully inside a transport
 *	session.
 *	The purpose of this test case is to get TSS_SUCCESS to be
 *		returned. This is accomplished by following the
 *		algorithm described below.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Get TPM Object
 *		Create hKey Object
 *		Get SRK Handle
 *		Get Policy Object (srk, tpm)
 *		Set secret (srk, tpm)
 *		Create Key (hkey, parent key, target key)
 *		Load key (parent key, hkey)
 *		Get Pub Key
 *		Set Attrib Data
 *		Authorize Migration Ticket
 *		LoadKeyByUUID
 *
 *	Test:	Call Key_ConvertMigrationBlob then if it is not a success
 *		make sure that it returns the proper return codes
 *
 *	Cleanup:
 *		Free memory associated with the context
 *		Close the hKey object
 *		Close the hParentStorageKey object
 *		Close the hTargetKey object
 *		Close the context.
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1 and 1.2
 *
 * HISTORY
 *	Author:	Kathy Robertson
 *	Date:	June 2004
 *	Email:	klrobert@us.ibm.com
 *	Revisions: Kent Yoder <kyoder@users.sf.net>
 *		EJR, ejratl@gmail.com, 8/10/2006, 1.2 updates
 *
 * RESTRICTIONS
 *	None.
 */

#include "common.h"


int main(int argc, char **argv)
{
	char version;

	version = parseArgs(argc, argv);
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
	char *nameOfFunction = "Tspi_Key_ConvertMigrationBlob-trans02";
	TSS_HCONTEXT hContext;
	TSS_HKEY hSRK;
	TSS_HKEY hKeyToMigrate, hKeyToMigrateInto;
	TSS_HKEY hMigrationAuthorityKey, hWrappingKey, hSigningKey;
	BYTE *MigTicket;
	UINT32 TicketLength;
	BYTE *randomData;
	UINT32 randomLength;
	UINT32 migBlobLength;
	BYTE *migBlob;
	TSS_RESULT result;
	TSS_HTPM hTPM;
	TSS_HPOLICY hUsagePolicy, hMigPolicy, tpmUsagePolicy;

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

	//Get Policy Object
	result =
	    Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &tpmUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Set Secret
	result =
	    Tspi_Policy_SetSecret(tpmUsagePolicy,
				  TESTSUITE_OWNER_SECRET_MODE,
				  TESTSUITE_OWNER_SECRET_LEN,
				  TESTSUITE_OWNER_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Create Object
	result =
	    Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
				      TSS_KEY_TYPE_STORAGE |
				      TSS_KEY_SIZE_2048 |
				      TSS_KEY_NO_AUTHORIZATION,
				      &hMigrationAuthorityKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Create Migrate Authority's key
	result = Tspi_Key_CreateKey(hMigrationAuthorityKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Create key Object
	result =
	    Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
				      TSS_KEY_TYPE_SIGNING |
				      TSS_KEY_SIZE_2048 |
				      TSS_KEY_NO_AUTHORIZATION |
				      TSS_KEY_MIGRATABLE, &hKeyToMigrate);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	// Create usage policy
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
					   TSS_POLICY_USAGE, &hUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Set Secret
	result = Tspi_Policy_SetSecret(hUsagePolicy, TESTSUITE_KEY_SECRET_MODE,
				       TESTSUITE_KEY_SECRET_LEN,
				       TESTSUITE_KEY_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Assign migration policy
	result = Tspi_Policy_AssignToObject(hUsagePolicy, hKeyToMigrate);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_AssignToObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Create migration policy
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY,
					   TSS_POLICY_MIGRATION, &hMigPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Set Secret
	result = Tspi_Policy_SetSecret(hMigPolicy, TESTSUITE_KEY_SECRET_MODE,
				       TESTSUITE_KEY_SECRET_LEN,
				       TESTSUITE_KEY_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Assign migration policy
	result = Tspi_Policy_AssignToObject(hMigPolicy, hKeyToMigrate);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_AssignToObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Create Key To Migrate
	result = Tspi_Key_CreateKey(hKeyToMigrate, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		Tspi_Context_Close(hContext);
		Tspi_Context_CloseObject(hContext, hKeyToMigrate);
		exit(result);
	}
	//Authorize Migration Ticket
	result =
	    Tspi_TPM_AuthorizeMigrationTicket(hTPM, hMigrationAuthorityKey,
					      TSS_MS_MIGRATE,
					      &TicketLength, &MigTicket);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_AuthorizeMigrationTicket ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result =
	    Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
				      TSS_KEY_TYPE_SIGNING |
				      TSS_KEY_SIZE_2048 |
				      TSS_KEY_NO_AUTHORIZATION |
				      TSS_KEY_MIGRATABLE,
				      &hKeyToMigrateInto);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Create Migration Blob
	result = Tspi_Key_CreateMigrationBlob(hKeyToMigrate, hSRK, TicketLength, MigTicket,
					      &randomLength, &randomData, &migBlobLength, &migBlob);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_AuthorizeMigrationTicket ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Key_LoadKey(hMigrationAuthorityKey, hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_TPM_AuthorizeMigrationTicket ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_ConvertMigrationBlob(hKeyToMigrateInto, hMigrationAuthorityKey,
					       randomLength, randomData, migBlobLength, migBlob);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_ConvertMigrationBlob", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Testsuite_Transport_Final(hContext, hSigningKey);
	if (result != TSS_SUCCESS) {
		if (!checkNonAPI(result)) {
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_Close(hContext);
			exit(result);
		} else {
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_Close(hContext);
			exit(result);
		}
	} else {
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(0);
	}
}
