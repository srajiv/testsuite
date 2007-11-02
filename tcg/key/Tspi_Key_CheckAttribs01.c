/*
 *
 *   Copyright (C) International Business Machines  Corp., 2006
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
 *	Tspi_Key_CheckAttribs.c
 *
 * DESCRIPTION
 *	This test will verify that the attributes set for a key in its object creation
 * 	are the same after Tspi_Key_CreateKey
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Create Object
 *		Load SRK By UUID
 *		Get Policy Object
 *		Set Secret
 *
 *	Test:	Call CreateKey. If it is not a success
 *		Make sure that it returns the proper return codes
 *
 *	Cleanup:
 *		Close hKey object
 *		Close context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.2
 *
 * HISTORY
 *	Ramon Brandao, ramongb@br.ibm.com, 9/07
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
		main_v1_2( version );
	else
		print_wrongVersion();
}

int
main_v1_2( char version)
{
	char *nameOfFunction = "Tspi_Key_CheckAttribs01";
	TSS_HCONTEXT hContext;
	TSS_HTPM hTPM;
	TSS_FLAG initFlagsA, initFlagsB;
	TSS_HKEY hKeyA, hKeyB;
	TSS_HKEY hSRK;
	TSS_RESULT result;
	TSS_HPOLICY srkUsagePolicy, keyUsagePolicy;
	UINT32	 keyAttribute;
	TSS_HPCRS	hPcrComposite;
	BYTE	rgbPcrValue[20];


	initFlagsA = TSS_KEY_TYPE_STORAGE | TSS_KEY_SIZE_2048 |
	TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION |
	TSS_KEY_NOT_MIGRATABLE;

	initFlagsB = TSS_KEY_STRUCT_KEY12 | TSS_KEY_TYPE_STORAGE | TSS_KEY_SIZE_2048 |
	TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;

	print_begin_test(nameOfFunction);

	//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create", result);
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
		//Create key Object A
	result =
		Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
				initFlagsA, &hKeyA);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject(A)", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Create key Object B
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
			initFlagsB, &hKeyB);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject(B)", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	//Load Key By UUID - Get the Wrapping key
	result = Tspi_Context_LoadKeyByUUID(hContext,
			TSS_PS_TYPE_SYSTEM, SRK_UUID,
			&hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
#ifndef TESTSUITE_NOAUTH_SRK
	//Get Policy Object
	result =
		Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Set Secret
	result =
		Tspi_Policy_SetSecret(srkUsagePolicy,
				TESTSUITE_SRK_SECRET_MODE,
				TESTSUITE_SRK_SECRET_LEN,
				TESTSUITE_SRK_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
#endif
	//Create Policy Object
	result =
		Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE,
				&keyUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Set Secret
	result =
		Tspi_Policy_SetSecret(keyUsagePolicy,
				TESTSUITE_KEY_SECRET_MODE,
				TESTSUITE_KEY_SECRET_LEN,
				TESTSUITE_KEY_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Assign policy to key A
	result = Tspi_Policy_AssignToObject(keyUsagePolicy, hKeyA);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_AssignToObject(A)", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Assign policy to key B
	result = Tspi_Policy_AssignToObject(keyUsagePolicy, hKeyB);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_AssignToObject(B)", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	//Create Key wrapped by SRK
	result = Tspi_Key_CreateKey(hKeyA, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey(A)", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	if (version == TESTSUITE_TEST_TSS_1_2) {
		/* Create Key B wrapped by SRK */
		result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_PCRS,
				TSS_PCRS_STRUCT_INFO_LONG, &hPcrComposite );
		if ( result != TSS_SUCCESS )
		{
			print_error( "Tspi_Context_CreateObject (hPcrComposite)",
					result );
			print_error_exit( nameOfFunction, err_string(result) );
			Tspi_Context_Close( hContext );
			exit( result );
		}
		//Set PCR Locality at release
		result = Tspi_PcrComposite_SetPcrLocality(hPcrComposite, TPM_LOC_ZERO);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_PcrComposite_SetLocality", result);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			exit(result);
		}

		memset(rgbPcrValue, 0x5a, sizeof(rgbPcrValue));

		result = Tspi_PcrComposite_SetPcrValue( hPcrComposite, 9, 20, rgbPcrValue );
		if ( result != TSS_SUCCESS )
		{
			print_error( "Tspi_PcrComposite_SetPcrValue", result );
			print_error_exit( nameOfFunction, err_string(result) );
			Tspi_Context_Close( hContext );
			exit( result );
		}

		result = Tspi_Key_CreateKey(hKeyB, hSRK, hPcrComposite);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Key_CreateKey(B)", result);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_CloseObject( hContext, hKeyA );
			Tspi_Context_CloseObject( hContext, hKeyB );
			Tspi_Context_CloseObject( hContext, hPcrComposite );
			Tspi_Context_Close(hContext);
			exit(result);
		}
	}

	////////////////////////////////////
	//Start retrieving the key attributes set in initFlags for A

		//First attrib - key type = STORAGE
	result = Tspi_GetAttribUint32(hKeyA, TSS_TSPATTRIB_KEY_INFO,
				TSS_TSPATTRIB_KEYINFO_USAGE, &keyAttribute );
	if ((result != TSS_SUCCESS) || (keyAttribute != TSS_KEYUSAGE_STORAGE)){
		if ( keyAttribute != TSS_KEYUSAGE_STORAGE){
			fprintf( stderr, "\tError(A1): Key Attribute value not expected: %u\n",
					keyAttribute);
			result = TSS_E_FAIL;
		}
		print_error("Tspi_GetAttribUint32(A1)", result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(result);
	} else
		fprintf( stdout, "\tSuccess(A1): Checked key type.\n");

		//Second attrib - Migratable key = FALSE
	result = Tspi_GetAttribUint32(hKeyA, TSS_TSPATTRIB_KEY_INFO,
			TSS_TSPATTRIB_KEYINFO_MIGRATABLE, &keyAttribute );
	if ((result != TSS_SUCCESS) || ( keyAttribute )){
		if ( keyAttribute ){
			fprintf( stderr, "\tError(A2): Key Attribute value not expected: %u\n",
					keyAttribute);
			result = TSS_E_FAIL;
		}
		print_error("Tspi_GetAttribUint32(A2)", result);	
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(result);
	}else
		fprintf( stdout, "\tSuccess(A2): Checked key migration.\n");

		//Third attrib - VOLATILE key = TRUE
	result = Tspi_GetAttribUint32(hKeyA, TSS_TSPATTRIB_KEY_INFO,
			TSS_TSPATTRIB_KEYINFO_VOLATILE, &keyAttribute );
	if ((result != TSS_SUCCESS) || ( !keyAttribute )){
		if ( !keyAttribute ){
			fprintf( stderr, "\tError(A3): Key Attribute value not expected: %u\n",
					keyAttribute);
			result = TSS_E_FAIL;
		}
		print_error("Tspi_GetAttribUint32(A3)", result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(result);
	}else
		fprintf( stdout, "\tSuccess(A3): Checked if volatile key.\n");

		//Fourth attrib - Authorization key = TRUE
	result = Tspi_GetAttribUint32(hKeyA, TSS_TSPATTRIB_KEY_INFO,
			TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE, &keyAttribute );
	if ((result != TSS_SUCCESS) || ( !keyAttribute )){
		if ( !keyAttribute ){
			fprintf( stderr, "\tError(A4): Key Attribute value not expected: %u\n",
					keyAttribute);
			result = TSS_E_FAIL;
		}
		print_error("Tspi_GetAttribUint32(A4)", result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(result);
	}else
		fprintf( stdout, "\tSuccess(A4): Checked if authorization key.\n");

	if (version == TESTSUITE_TEST_TSS_1_2) {
		//Fifth attrib - CMK key = FALSE
		result = Tspi_GetAttribUint32(hKeyA, TSS_TSPATTRIB_KEY_INFO,
				TSS_TSPATTRIB_KEYINFO_CMK, &keyAttribute );
		if ((result != TSS_SUCCESS) || ( keyAttribute )){
			if ( keyAttribute ){
				fprintf( stderr, "\tError(A5): Key Attribute value not expected: %u\n",
						keyAttribute);
				result = TSS_E_FAIL;
			}
			print_error("Tspi_GetAttribUint32(A5)", result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(result);
		}else
			fprintf( stdout, "\tSuccess(A5): Checked if CMK key.\n");
	}

		//Sixth attrib - key SIZE = 2048 bits
	result = Tspi_GetAttribUint32(hKeyA, TSS_TSPATTRIB_RSAKEY_INFO,
			TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE, &keyAttribute );
	if ((result != TSS_SUCCESS) || ( keyAttribute != 2048 )){
		if ( keyAttribute != 2048 ){
			fprintf( stderr, "\tError(A6): Key Attribute value not expected: %u\n",
					keyAttribute);
			result = TSS_E_FAIL;
		}
		print_error("Tspi_GetAttribUint32(A6)", result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
		exit(result);
	}else
		fprintf( stdout, "\tSuccess(A6): Checked RSA key size.\n");


	if (version == TESTSUITE_TEST_TSS_1_2) {
		////////////////////////////////////
		//Start retrieving the key attributes set in initFlags for B

		//First attrib - key type = STORAGE
		result = Tspi_GetAttribUint32(hKeyB, TSS_TSPATTRIB_KEY_INFO,
				TSS_TSPATTRIB_KEYINFO_USAGE, &keyAttribute );
		if ((result != TSS_SUCCESS) || (keyAttribute != TSS_KEYUSAGE_STORAGE)){
			if ( keyAttribute != TSS_KEYUSAGE_STORAGE){
				fprintf( stderr, "\tError(B1): Key Attribute value not expected: %u\n",
						keyAttribute);
				result = TSS_E_FAIL;
			}
			print_error("Tspi_GetAttribUint32(B1)", result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(result);
		}else
			fprintf( stdout, "\tSuccess(B1): Checked key type.\n");

		//Second attrib - Migratable key = FALSE
		result = Tspi_GetAttribUint32(hKeyB, TSS_TSPATTRIB_KEY_INFO,
				TSS_TSPATTRIB_KEYINFO_MIGRATABLE, &keyAttribute );
		if ((result != TSS_SUCCESS) || ( keyAttribute )){
			if ( keyAttribute ){
				fprintf( stderr, "\tError(B2): Key Attribute value not expected: %u\n",
						keyAttribute);
				result = TSS_E_FAIL;
			}
			print_error("Tspi_GetAttribUint32(B2)", result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(result);
		}else
			fprintf( stdout, "\tSuccess(B2): Checked key migration.\n");

		//Third attrib - VOLATILE key = FALSE
		result = Tspi_GetAttribUint32(hKeyB, TSS_TSPATTRIB_KEY_INFO,
				TSS_TSPATTRIB_KEYINFO_VOLATILE, &keyAttribute );
		if ((result != TSS_SUCCESS) || ( keyAttribute )){
			if ( keyAttribute ){
				fprintf( stderr, "\tError(B3): Key Attribute value not expected: %u\n",
						keyAttribute);
				result = TSS_E_FAIL;
			}
			print_error("Tspi_GetAttribUint32(B3)", result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(result);
		}else
			fprintf( stdout, "\tSuccess(B3): Checked if volatile key.\n");

		//Fourth attrib - Authorization key = FALSE
		result = Tspi_GetAttribUint32(hKeyB, TSS_TSPATTRIB_KEY_INFO,
				TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE, &keyAttribute );
		if ((result != TSS_SUCCESS) || ( keyAttribute )){
			if ( keyAttribute ){
				fprintf( stderr, "\tError(B4): Key Attribute value not expected: %u\n",
						keyAttribute);
				result = TSS_E_FAIL;
			}
			print_error("Tspi_GetAttribUint32(B4)", result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(result);
		}else
			fprintf( stdout, "\tSuccess(B4): Checked if authorization key.\n");

		//Fifth attrib - CMK key = FALSE
		result = Tspi_GetAttribUint32(hKeyB, TSS_TSPATTRIB_KEY_INFO,
				TSS_TSPATTRIB_KEYINFO_CMK, &keyAttribute );
		if ((result != TSS_SUCCESS) || ( keyAttribute )){
			if ( keyAttribute ){
				fprintf( stderr, "\tError(B5): Key Attribute value not expected: %u\n",
						keyAttribute);
				result = TSS_E_FAIL;
			}
			print_error("Tspi_GetAttribUint32(B5)", result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(result);
		}else
			fprintf( stdout, "\tSuccess(B5): Checked if CMK key.\n");

		//Sixth attrib - key SIZE = 512 bits
		result = Tspi_GetAttribUint32(hKeyB, TSS_TSPATTRIB_RSAKEY_INFO,
				TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE, &keyAttribute );
		if ((result != TSS_SUCCESS) || ( keyAttribute != 2048 )){
			if ( keyAttribute != 512 ){
				fprintf( stderr, "\tError(B6): Key Attribute value not expected: %u\n",
						keyAttribute);
				result = TSS_E_FAIL;
			}
			print_error("Tspi_GetAttribUint32(B6)", result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(result);
		}else
			fprintf( stdout, "\tSuccess(B6): Checked RSA key size.\n");

		//Seventh attrib - keyB PcrComposite LocalityAtRelease = TPM_LOC_ZERO
		result = Tspi_GetAttribUint32(hKeyB, TSS_TSPATTRIB_KEY_PCR_LONG,
				TSS_TSPATTRIB_KEYPCRLONG_LOCALITY_ATRELEASE, &keyAttribute );
		if ((result != TSS_SUCCESS) || ( keyAttribute != TPM_LOC_ZERO )){
			if ( keyAttribute != TPM_LOC_ZERO ){
				fprintf( stderr, "\tError(B7): Key Attribute value not expected: %u\n",
						keyAttribute);
				result = TSS_E_FAIL;
			}
			print_error("Tspi_GetAttribUint32(B7)", result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			exit(result);
		}else
			fprintf( stdout, "\tSuccess(B7): Checked PCR Locality at Release.\n");
	}


	print_success(nameOfFunction, result);
	print_end_test(nameOfFunction);
	Tspi_Context_Close(hContext);
	exit(0);

}
