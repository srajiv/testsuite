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
 *      common.c
 *
 * DESCRIPTION
 *      This file contains a function to translate errors into strings,
 *	for the purpose of printed error statements. It also contains
 *	a function to assign an integer to a byte array.
 *
 * ALGORITHM
 *      None.
 *
 * USAGE
 *      Include common.o in compile arguments
 *
 * HISTORY
 *
 * RESTRICTIONS
 *      None.
 */

#include <stdio.h>
#include <wchar.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>

#include "trousers/tss.h"
#include "common.h"

TSS_UUID SRK_UUID = TSS_UUID_SRK;

struct option long_options[] = {
	{"version",	required_argument,	NULL,	'v'},
	{0,0,0,0}
};
void
print_wrongVersion()
{
	fprintf( stderr,
		"At this time this version is currently unimplemented\n" );
	exit(1);
}
void
print_wrongChar()
{
	fprintf( stderr, "You entered an incorrect parameter \n" );
	exit(1);
}
void printUsage()
{
	fprintf( stderr, "Usage: --options\n" );
	fprintf( stderr, "\t-v or --version\t\tThe version of the TSS you would like to test.\n" );
}
char* parseArgs(int argc, char **argv)
{
	int option_index;
	int c;
	char *version;

	if (argc <3){
		printUsage();
		exit(1);
	}

	while ((c = getopt_long(argc, argv, "v:", long_options,
				&option_index)) != EOF){
		switch(c){
			case 'v':
				version = strdup(optarg);
				break;
			case ':':
				//fall through
			case '?':
				//fall through
			default:
				print_wrongChar();
				printUsage();
				exit(0);
		}
	}
	return version;
}
int checkNonAPI(TSS_RESULT result){
	/* allow all TPM errors to fall within the API */
	if (   (TSS_ERROR_LAYER(result) == TSS_LAYER_TPM) ||
		(TSS_ERROR_CODE(result) == TSS_E_INVALID_HANDLE) ||
		(TSS_ERROR_CODE(result) == TSS_E_INTERNAL_ERROR) ||
		(TSS_ERROR_CODE(result) == TSS_E_BAD_PARAMETER) ||
		(TSS_ERROR_CODE(result) == TSS_E_KEY_NO_MIGRATION_POLICY) ||
		(TSS_ERROR_CODE(result) == TSS_E_FAIL) ||
		(TSS_ERROR_CODE(result) == TSS_E_NOTIMPL) ||
		(TSS_ERROR_CODE(result) == TSS_E_PS_KEY_NOTFOUND) ||
		(TSS_ERROR_CODE(result) == TSS_E_KEY_ALREADY_REGISTERED) ||
		(TSS_ERROR_CODE(result) == TSS_E_CANCELED) ||
		(TSS_ERROR_CODE(result) == TSS_E_TIMEOUT) ||
		(TSS_ERROR_CODE(result) == TSS_E_OUTOFMEMORY) ||
		(TSS_ERROR_CODE(result) == TSS_E_TPM_UNEXPECTED) ||
		(TSS_ERROR_CODE(result) == TSS_E_COMM_FAILURE) ||
		(TSS_ERROR_CODE(result) == TSS_E_TPM_UNSUPPORTED_FEATURE) ||
		(TSS_ERROR_CODE(result) == TSS_E_INVALID_OBJECT_TYPE) ||
		(TSS_ERROR_CODE(result) == TSS_E_INVALID_OBJECT_INITFLAG) ||
		(TSS_ERROR_CODE(result) == TSS_E_NO_CONNECTION) ||
		(TSS_ERROR_CODE(result) == TSS_E_CONNECTION_FAILED) ||
		(TSS_ERROR_CODE(result) == TSS_E_CONNECTION_BROKEN) ||
		(TSS_ERROR_CODE(result) == TSS_E_HASH_INVALID_ALG) ||
		(TSS_ERROR_CODE(result) == TSS_E_HASH_INVALID_LENGTH) ||
		(TSS_ERROR_CODE(result) == TSS_E_HASH_NO_DATA) ||
		(TSS_ERROR_CODE(result) == TSS_E_SILENT_CONTEXT) ||
		(TSS_ERROR_CODE(result) == TSS_E_INVALID_ATTRIB_FLAG) ||
		(TSS_ERROR_CODE(result) == TSS_E_INVALID_ATTRIB_SUBFLAG) ||
		(TSS_ERROR_CODE(result) == TSS_E_NO_PCRS_SET) ||
		(TSS_ERROR_CODE(result) == TSS_E_KEY_NOT_LOADED) ||
		(TSS_ERROR_CODE(result) == TSS_E_KEY_NOT_SET) ||
		(TSS_ERROR_CODE(result) == TSS_E_VALIDATION_FAILED) ||
		(TSS_ERROR_CODE(result) == TSS_E_TSP_AUTHREQUIRED) ||
		(TSS_ERROR_CODE(result) == TSS_E_TSP_AUTH2REQUIRED) ||
		(TSS_ERROR_CODE(result) == TSS_E_TSP_AUTHFAIL) ||
		(TSS_ERROR_CODE(result) == TSS_E_TSP_AUTH2FAIL) ||
		(TSS_ERROR_CODE(result) == TSS_E_KEY_NO_MIGRATION_POLICY) ||
		(TSS_ERROR_CODE(result) == TSS_E_POLICY_NO_SECRET) ||
		(TSS_ERROR_CODE(result) == TSS_E_INVALID_OBJ_ACCESS) ||
		(TSS_ERROR_CODE(result) == TSS_E_INVALID_ENCSCHEME) ||
		(TSS_ERROR_CODE(result) == TSS_E_INVALID_SIGSCHEME) ||
		(TSS_ERROR_CODE(result) == TSS_E_ENC_INVALID_LENGTH) ||
		(TSS_ERROR_CODE(result) == TSS_E_ENC_NO_DATA) ||
		(TSS_ERROR_CODE(result) == TSS_E_ENC_INVALID_TYPE) ||
		(TSS_ERROR_CODE(result) == TSS_E_INVALID_KEYUSAGE) ||
		(TSS_ERROR_CODE(result) == TSS_E_VERIFICATION_FAILED) ||
		(TSS_ERROR_CODE(result) == TSS_E_HASH_NO_IDENTIFIER) ||
		(TSS_ERROR_CODE(result) == TSS_SUCCESS))
			return 0;

	else
		return 1;
}

void
UINT32ToArray(UINT32 i, BYTE * out)
{
	out[0] = (BYTE) ((i >> 24) & 0xFF);
	out[1] = (BYTE) ((i >> 16) & 0xFF);
	out[2] = (BYTE) ((i >> 8) & 0xFF);
	out[3] = (BYTE) (i & 0xFF);
	return;
}

void
print_hex( BYTE *buf, UINT32 len )
{
	UINT32 i = 0, j;

	while (i < len) {
		for (j=0; (j < 15) && (i < len); j++, i++)
			printf("%02x ", buf[i] & 0xff);
		printf("\n");
	}
}

char *
err_string(TSS_RESULT r)
{
	/* Check the return code to see if it is common to all layers.
	 * If so, return it.
	 */
	switch (TSS_ERROR_CODE(r)) {
		case TSS_SUCCESS:			return "TSS_SUCCESS";
		default:
			break;
	}

	/* The return code is either unknown, or specific to a layer */
	if (TSS_ERROR_LAYER(r) == TSS_LAYER_TPM) {
		switch (TSS_ERROR_CODE(r)) {
			case TCPA_E_AUTHFAIL:		return "TCPA_E_AUTHFAIL";
			case TCPA_E_BADINDEX:		return "TCPA_E_BADINDEX";
			case TCPA_E_AUDITFAILURE:	return "TCPA_E_AUDITFAILURE";
			case TCPA_E_CLEAR_DISABLED:	return "TCPA_E_CLEAR_DISABLED";
			case TCPA_E_DEACTIVATED:	return "TCPA_E_DEACTIVATED";
			case TCPA_E_DISABLED:		return "TCPA_E_DISABLED";
			case TCPA_E_DISABLED_CMD:	return "TCPA_E_DISABLED_CMD";
			case TCPA_E_FAIL:		return "TCPA_E_FAIL";
			case TCPA_E_INACTIVE:		return "TCPA_E_INACTIVE";
			case TCPA_E_INSTALL_DISABLED:	return "TCPA_E_INSTALL_DISABLED";
			case TCPA_E_INVALID_KEYHANDLE:	return "TCPA_E_INVALID_KEYHANDLE";
			case TCPA_E_KEYNOTFOUND:	return "TCPA_E_KEYNOTFOUND";
			case TCPA_E_NEED_SELFTEST:	return "TCPA_E_NEED_SELFTEST";
			case TCPA_E_MIGRATEFAIL:	return "TCPA_E_MIGRATEFAIL";
			case TCPA_E_NO_PCR_INFO:	return "TCPA_E_NO_PCR_INFO";
			case TCPA_E_NOSPACE:		return "TCPA_E_NOSPACE";
			case TCPA_E_NOSRK:		return "TCPA_E_NOSRK";
			case TCPA_E_NOTSEALED_BLOB:	return "TCPA_E_NOTSEALED_BLOB";
			case TCPA_E_OWNER_SET:		return "TCPA_E_OWNER_SET";
			case TCPA_E_RESOURCES:		return "TCPA_E_RESOURCES";
			case TCPA_E_SHORTRANDOM:	return "TCPA_E_SHORTRANDOM";
			case TCPA_E_SIZE:		return "TCPA_E_SIZE";
			case TCPA_E_WRONGPCRVAL:	return "TCPA_E_WRONGPCRVAL";
			case TCPA_E_BAD_PARAM_SIZE:	return "TCPA_E_BAD_PARAM_SIZE";
			case TCPA_E_SHA_THREAD:		return "TCPA_E_SHA_THREAD";
			case TCPA_E_SHA_ERROR:		return "TCPA_E_SHA_ERROR";
			case TCPA_E_FAILEDSELFTEST:	return "TCPA_E_FAILEDSELFTEST";
			case TCPA_E_AUTH2FAIL:		return "TCPA_E_AUTH2FAIL";
			case TCPA_E_BADTAG:		return "TCPA_E_BADTAG";
			case TCPA_E_IOERROR:		return "TCPA_E_IOERROR";
			case TCPA_E_ENCRYPT_ERROR:	return "TCPA_E_ENCRYPT_ERROR";
			case TCPA_E_DECRYPT_ERROR:	return "TCPA_E_DECRYPT_ERROR";
			case TCPA_E_INVALID_AUTHHANDLE:	return "TCPA_E_INVALID_AUTHHANDLE";
			case TCPA_E_NO_ENDORSEMENT:	return "TCPA_E_NO_ENDORSEMENT";
			case TCPA_E_INVALID_KEYUSAGE:	return "TCPA_E_INVALID_KEYUSAGE";
			case TCPA_E_WRONG_ENTITYTYPE:	return "TCPA_E_WRONG_ENTITYTYPE";
			case TCPA_E_INVALID_POSTINIT:	return "TCPA_E_INVALID_POSTINIT";
			case TCPA_E_INAPPROPRIATE_SIG:	return "TCPA_E_INAPPROPRIATE_SIG";
			case TCPA_E_BAD_KEY_PROPERTY:	return "TCPA_E_BAD_KEY_PROPERTY";
			case TCPA_E_BAD_MIGRATION:	return "TCPA_E_BAD_MIGRATION";
			case TCPA_E_BAD_SCHEME:		return "TCPA_E_BAD_SCHEME";
			case TCPA_E_BAD_DATASIZE:	return "TCPA_E_BAD_DATASIZE";
			case TCPA_E_BAD_MODE:		return "TCPA_E_BAD_MODE";
			case TCPA_E_BAD_PRESENCE:	return "TCPA_E_BAD_PRESENCE";
			case TCPA_E_BAD_VERSION:	return "TCPA_E_BAD_VERSION";
			case TCPA_E_RETRY:		return "TCPA_E_RETRY";
			default:			return "UNKNOWN TPM ERROR";
		}
	} else if (TSS_ERROR_LAYER(r) == TSS_LAYER_TDDL) {
		switch (TSS_ERROR_CODE(r)) {
			case TSS_E_FAIL:			return "TSS_E_FAIL";
			case TSS_E_BAD_PARAMETER:		return "TSS_E_BAD_PARAMETER";
			case TSS_E_INTERNAL_ERROR:		return "TSS_E_INTERNAL_ERROR";
			case TSS_E_NOTIMPL:			return "TSS_E_NOTIMPL";
			case TSS_E_PS_KEY_NOTFOUND:		return "TSS_E_PS_KEY_NOTFOUND";
			case TSS_E_KEY_ALREADY_REGISTERED:	return "TSS_E_KEY_ALREADY_REGISTERED";
			case TSS_E_CANCELED:			return "TSS_E_CANCELED";
			case TSS_E_TIMEOUT:			return "TSS_E_TIMEOUT";
			case TSS_E_OUTOFMEMORY:			return "TSS_E_OUTOFMEMORY";
			case TSS_E_TPM_UNEXPECTED:		return "TSS_E_TPM_UNEXPECTED";
			case TSS_E_COMM_FAILURE:		return "TSS_E_COMM_FAILURE";
			case TSS_E_TPM_UNSUPPORTED_FEATURE:	return "TSS_E_TPM_UNSUPPORTED_FEATURE";
			case TDDL_E_COMPONENT_NOT_FOUND:	return "TDDL_E_COMPONENT_NOT_FOUND";
			case TDDL_E_ALREADY_OPENED:		return "TDDL_E_ALREADY_OPENED";
			case TDDL_E_BADTAG:			return "TDDL_E_BADTAG";
			case TDDL_E_INSUFFICIENT_BUFFER:	return "TDDL_E_INSUFFICIENT_BUFFER";
			case TDDL_E_COMMAND_COMPLETED:		return "TDDL_E_COMMAND_COMPLETED";
			case TDDL_E_ALREADY_CLOSED:		return "TDDL_E_ALREADY_CLOSED";
			case TDDL_E_IOERROR:			return "TDDL_E_IOERROR";
			default:				return "UNKNOWN TDDL ERROR";
		}
	} else if (TSS_ERROR_LAYER(r) == TSS_LAYER_TCS) {
		switch (TSS_ERROR_CODE(r)) {
			case TSS_E_FAIL:			return "TSS_E_FAIL";
			case TSS_E_BAD_PARAMETER:		return "TSS_E_BAD_PARAMETER";
			case TSS_E_INTERNAL_ERROR:		return "TSS_E_INTERNAL_ERROR";
			case TSS_E_NOTIMPL:			return "TSS_E_NOTIMPL";
			case TSS_E_PS_KEY_NOTFOUND:		return "TSS_E_PS_KEY_NOTFOUND";
			case TSS_E_KEY_ALREADY_REGISTERED:	return "TSS_E_KEY_ALREADY_REGISTERED";
			case TSS_E_CANCELED:			return "TSS_E_CANCELED";
			case TSS_E_TIMEOUT:			return "TSS_E_TIMEOUT";
			case TSS_E_OUTOFMEMORY:			return "TSS_E_OUTOFMEMORY";
			case TSS_E_TPM_UNEXPECTED:		return "TSS_E_TPM_UNEXPECTED";
			case TSS_E_COMM_FAILURE:		return "TSS_E_COMM_FAILURE";
			case TSS_E_TPM_UNSUPPORTED_FEATURE:	return "TSS_E_TPM_UNSUPPORTED_FEATURE";
			case TCS_E_KEY_MISMATCH:		return "TCS_E_KEY_MISMATCH";
			case TCS_E_KM_LOADFAILED:		return "TCS_E_KM_LOADFAILED";
			case TCS_E_KEY_CONTEXT_RELOAD:		return "TCS_E_KEY_CONTEXT_RELOAD";
			case TCS_E_INVALID_CONTEXTHANDLE:	return "TCS_E_INVALID_CONTEXTHANDLE";
			case TCS_E_INVALID_KEYHANDLE:		return "TCS_E_INVALID_KEYHANDLE";
			case TCS_E_INVALID_AUTHHANDLE:		return "TCS_E_INVALID_AUTHHANDLE";
			case TCS_E_INVALID_AUTHSESSION:		return "TCS_E_INVALID_AUTHSESSION";
			case TCS_E_INVALID_KEY:			return "TCS_E_INVALID_KEY";
			default:				return "UNKNOWN TCS ERROR";
		}
	} else {
		switch (TSS_ERROR_CODE(r)) {
			case TSS_E_FAIL:			return "TSS_E_FAIL";
			case TSS_E_BAD_PARAMETER:		return "TSS_E_BAD_PARAMETER";
			case TSS_E_INTERNAL_ERROR:		return "TSS_E_INTERNAL_ERROR";
			case TSS_E_NOTIMPL:			return "TSS_E_NOTIMPL";
			case TSS_E_PS_KEY_NOTFOUND:		return "TSS_E_PS_KEY_NOTFOUND";
			case TSS_E_KEY_ALREADY_REGISTERED:	return "TSS_E_KEY_ALREADY_REGISTERED";
			case TSS_E_CANCELED:			return "TSS_E_CANCELED";
			case TSS_E_TIMEOUT:			return "TSS_E_TIMEOUT";
			case TSS_E_OUTOFMEMORY:			return "TSS_E_OUTOFMEMORY";
			case TSS_E_TPM_UNEXPECTED:		return "TSS_E_TPM_UNEXPECTED";
			case TSS_E_COMM_FAILURE:		return "TSS_E_COMM_FAILURE";
			case TSS_E_TPM_UNSUPPORTED_FEATURE:	return "TSS_E_TPM_UNSUPPORTED_FEATURE";
			case TSS_E_INVALID_OBJECT_TYPE:		return "TSS_E_INVALID_OBJECT_TYPE";
			case TSS_E_INVALID_OBJECT_INITFLAG:	return "TSS_E_INVALID_OBJECT_INITFLAG";
			case TSS_E_INVALID_HANDLE:		return "TSS_E_INVALID_HANDLE";
			case TSS_E_NO_CONNECTION:		return "TSS_E_NO_CONNECTION";
			case TSS_E_CONNECTION_FAILED:		return "TSS_E_CONNECTION_FAILED";
			case TSS_E_CONNECTION_BROKEN:		return "TSS_E_CONNECTION_BROKEN";
			case TSS_E_HASH_INVALID_ALG:		return "TSS_E_HASH_INVALID_ALG";
			case TSS_E_HASH_INVALID_LENGTH:		return "TSS_E_HASH_INVALID_LENGTH";
			case TSS_E_HASH_NO_DATA:		return "TSS_E_HASH_NO_DATA";
			case TSS_E_SILENT_CONTEXT:		return "TSS_E_SILENT_CONTEXT";
			case TSS_E_INVALID_ATTRIB_FLAG:		return "TSS_E_INVALID_ATTRIB_FLAG";
			case TSS_E_INVALID_ATTRIB_SUBFLAG:	return "TSS_E_INVALID_ATTRIB_SUBFLAG";
			case TSS_E_INVALID_ATTRIB_DATA:		return "TSS_E_INVALID_ATTRIB_DATA";
			case TSS_E_NO_PCRS_SET:			return "TSS_E_NO_PCRS_SET";
			case TSS_E_KEY_NOT_LOADED:		return "TSS_E_KEY_NOT_LOADED";
			case TSS_E_KEY_NOT_SET:			return "TSS_E_KEY_NOT_SET";
			case TSS_E_VALIDATION_FAILED:		return "TSS_E_VALIDATION_FAILED";
			case TSS_E_TSP_AUTHREQUIRED:		return "TSS_E_TSP_AUTHREQUIRED";
			case TSS_E_TSP_AUTH2REQUIRED:		return "TSS_E_TSP_AUTH2REQUIRED";
			case TSS_E_TSP_AUTHFAIL:		return "TSS_E_TSP_AUTHFAIL";
			case TSS_E_TSP_AUTH2FAIL:		return "TSS_E_TSP_AUTH2FAIL";
			case TSS_E_KEY_NO_MIGRATION_POLICY:	return "TSS_E_KEY_NO_MIGRATION_POLICY";
			case TSS_E_POLICY_NO_SECRET:		return "TSS_E_POLICY_NO_SECRET";
			case TSS_E_INVALID_OBJ_ACCESS:		return "TSS_E_INVALID_OBJ_ACCESS";
			case TSS_E_INVALID_ENCSCHEME:		return "TSS_E_INVALID_ENCSCHEME";
			case TSS_E_INVALID_SIGSCHEME:		return "TSS_E_INVALID_SIGSCHEME";
			case TSS_E_ENC_INVALID_LENGTH:		return "TSS_E_ENC_INVALID_LENGTH";
			case TSS_E_ENC_NO_DATA:			return "TSS_E_ENC_NO_DATA";
			case TSS_E_ENC_INVALID_TYPE:		return "TSS_E_ENC_INVALID_TYPE";
			case TSS_E_INVALID_KEYUSAGE:		return "TSS_E_INVALID_KEYUSAGE";
			case TSS_E_VERIFICATION_FAILED:		return "TSS_E_VERIFICATION_FAILED";
			case TSS_E_HASH_NO_IDENTIFIER:		return "TSS_E_HASH_NO_IDENTIFIER";
			default:				return "UNKNOWN TSS ERROR";
		}
	}
}

/* functions provided to ease testcase writing */

/* create a key off the SRK */
TSS_RESULT
create_key(TSS_HCONTEXT hContext, TSS_FLAG initFlags,
		TSS_HKEY hSRK, TSS_HKEY *hKey)
{
	TSS_RESULT result;

		//Create Object
	result = Tspi_Context_CreateObject(hContext,
			TSS_OBJECT_TYPE_RSAKEY,
			initFlags, hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		return(result);
	}

	if (initFlags & TSS_KEY_AUTHORIZATION) {
		if ((result = set_secret(*hKey, NULL)))
			return result;
	}

		//CreateKey
	result = Tspi_Key_CreateKey(*hKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		return(result);
	}

	return TSS_SUCCESS;
}

/* create and load a key off the SRK */
TSS_RESULT
create_load_key(TSS_HCONTEXT hContext, TSS_FLAG initFlags,
		TSS_HKEY hSRK, TSS_HKEY *hKey)
{
	TSS_RESULT result;

	if ((result = create_key(hContext, initFlags, hSRK, hKey)))
		return result;

	result = Tspi_Key_LoadKey(*hKey, hSRK);
        if (result != TSS_SUCCESS) {
                print_error("Tspi_Key_LoadKey", result);
                return(result);
        }

	return TSS_SUCCESS;
}

/* set the secret for an object to a 0 length string */
TSS_RESULT
set_secret(TSS_HOBJECT hObj, TSS_HPOLICY *hPolicy)
{
	TSS_RESULT result;
	TSS_HPOLICY hLocalPolicy;

	if (hPolicy == NULL) {
		//GetPolicyObject
		result = Tspi_GetPolicyObject(hObj, TSS_POLICY_USAGE, &hLocalPolicy);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_GetPolicyObject", result);
			return(result);
		}
		//SetSecret
		result = Tspi_Policy_SetSecret(hLocalPolicy, TSS_SECRET_MODE_PLAIN,
				0, NULL);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Policy_SetSecret", result);
			return(result);
		}
	} else {
		//GetPolicyObject
		result = Tspi_GetPolicyObject(hObj, TSS_POLICY_USAGE, hPolicy);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_GetPolicyObject", result);
			return(result);
		}
		//SetSecret
		result = Tspi_Policy_SetSecret(*hPolicy, TSS_SECRET_MODE_PLAIN,
				0, NULL);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Policy_SetSecret", result);
			return(result);
		}
	}

	return TSS_SUCCESS;
}

/* connect, load the SRK */
TSS_RESULT
connect_load_srk(TSS_HCONTEXT *hContext, TSS_HKEY *hSRK)
{
	TSS_RESULT result;

		// Create Context
	result = Tspi_Context_Create( hContext );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Create", result );
		return( result );
	}

		// Connect to Context
	result = Tspi_Context_Connect( *hContext, get_server(GLOBALSERVER) );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Connect", result );
		Tspi_Context_FreeMemory( *hContext, NULL );
		Tspi_Context_Close( *hContext );
		return( result );
	}

		//Load Key by UUID for SRK
	result = Tspi_Context_LoadKeyByUUID(*hContext, TSS_PS_TYPE_SYSTEM,
			SRK_UUID, hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID", result);
		Tspi_Context_Close(*hContext);
		return(result);
	}

	if ((result = set_secret(*hSRK, NULL))) {
		Tspi_Context_Close(*hContext);
		return result;
	}

	return TSS_SUCCESS;
}

/* connect, load the SRK and get the TPM handle */
TSS_RESULT
connect_load_all(TSS_HCONTEXT *hContext, TSS_HKEY *hSRK, TSS_HTPM *hTPM)
{
	TSS_RESULT result;

	if ((result = connect_load_srk(hContext, hSRK)))
		return result;

		// Retrieve TPM object of context
	result = Tspi_Context_GetTpmObject( *hContext, hTPM );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_GetTpmObject", result );
		Tspi_Context_FreeMemory( *hContext, NULL );
		Tspi_Context_Close( *hContext );
		return( result );
	}

	return TSS_SUCCESS;
}

TSS_RESULT
bind_and_unbind(TSS_HCONTEXT hContext, TSS_HKEY hKey)
{

	TSS_RESULT result;
	TSS_HENCDATA hEncData;
	BYTE rgbDataToBind[] = "932brh3270yrnc7y0nrj28c89cjrmj4398jng4399mch8";
	UINT32 ulDataLength = sizeof(rgbDataToBind);
	BYTE *rgbEncryptedData, *prgbDataToUnBind;
	UINT32 ulEncryptedDataLength, pulDataLength;

	result = Tspi_Context_CreateObject( hContext,
					    TSS_OBJECT_TYPE_ENCDATA,
					    TSS_ENCDATA_BIND, &hEncData );
	if ( result != TSS_SUCCESS )
	{
		print_error("Tspi_Context_CreateObject ", result);
		return result;
	}

	printf("Data before binding:\n");
	print_hex(rgbDataToBind, ulDataLength);

	result = Tspi_Data_Bind( hEncData, hKey, ulDataLength, rgbDataToBind );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Data_Bind", result );
		return result;
	}

	result = Tspi_GetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB,
			TSS_TSPATTRIB_ENCDATABLOB_BLOB,
			&ulEncryptedDataLength, &rgbEncryptedData);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetAttribData", result );
		return result;
	}

	printf("Data after binding:\n");
	print_hex(rgbEncryptedData, ulEncryptedDataLength);

	result = Tspi_Data_Unbind( hEncData, hKey, &pulDataLength,
			&prgbDataToUnBind );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Data_Unbind", result );
		if( !(checkNonAPI(result)) )
		{
			print_error( "Tspi_Data_Unbind", result );
		}
		else
		{
			print_error_nonapi( "Tspi_Data_Unbind", result );
		}
	}
	else
	{
		printf("Data after unbinding:\n");
		print_hex(prgbDataToUnBind, pulDataLength);

		if (pulDataLength != ulDataLength) {
			printf("ERROR: Size of decrypted data does not match!"
			       " (%u != %u)\n", pulDataLength, ulDataLength);
			result = TSS_E_FAIL;
		} else if (memcmp(prgbDataToUnBind, rgbDataToBind, ulDataLength)) {
			printf("ERROR: Content of decrypted data does not match!\n");
			result = TSS_E_FAIL;
		} else {
			result = TSS_SUCCESS;
		}
	}

	return result;
}

