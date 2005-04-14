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

#include "tss/tss.h"

char
*err_string(TSS_RESULT r)
{
	char *rv;

	switch (r) {
		case TSS_SUCCESS:
			rv = "TSS_SUCCESS";
			break;
		case TSS_E_FAIL:
			rv = "TSS_E_FAIL";
			break;
		case TSS_E_BAD_PARAMETER:
			rv = "TSS_E_BAD_PARAMETER";
			break;
		case TSS_E_INTERNAL_ERROR:
			rv = "TSS_E_INTERNAL_ERROR";
			break;
		case TSS_E_NOTIMPL:
			rv = "TSS_E_NOTIMPL";
			break;
		case TSS_E_PS_KEY_NOTFOUND:
			rv = "TSS_E_PS_KEY_NOTFOUND";
			break;
		case TSS_E_KEY_ALREADY_REGISTERED:
			rv = "TSS_E_KEY_ALREADY_REGISTERED";
			break;
		case TSS_E_CANCELLED:
			rv = "TSS_E_CANCELLED";
			break;
		case TSS_E_TIMEOUT:
			rv = "TSS_E_TIMEOUT";
			break;
		case TSS_E_OUTOFMEMORY:
			rv = "TSS_E_OUTOFMEMORY";
			break;
		case TSS_E_TPM_UNEXPECTED:
			rv = "TSS_E_TPM_UNEXPECTED";
			break;
		case TSS_E_COMM_FAILURE:
			rv = "TSS_E_COMM_FAILURE";
			break;
		case TSS_E_TPM_UNSUPPORTED_FEATURE:
			rv = "TSS_E_TPM_UNSUPPORTED_FEATURE";
			break;
		case TDDL_E_FAIL:
			rv = "TDDL_E_FAIL";
			break;
		case TDDL_E_BAD_PARAMETER:
			rv = "TDDL_E_BAD_PARAMETER";
			break;
		case TDDL_E_COMPONENT_NOT_FOUND:
			rv = "TDDL_E_COMPONENT_NOT_FOUND";
			break;
		case TDDL_E_ALREADY_OPENED:
			rv = "TDDL_E_ALREADY_OPENED";
			break;
		case TDDL_E_BADTAG:
			rv = "TDDL_E_BADTAG";
			break;
		case TDDL_E_TIMEOUT:
			rv = "TDDL_E_TIMEOUT";
			break;
		case TDDL_E_INSUFFICIENT_BUFFER:
			rv = "TDDL_E_INSUFFICIENT_BUFFER";
			break;
		case TDDL_COMMAND_COMPLETED:
			rv = "TDDL_COMMAND_COMPLETED";
			break;
		case TDDL_E_OUTOFMEMORY:
			rv = "TDDL_E_OUTOFMEMORY";
			break;
		case TDDL_E_ALREADY_CLOSED:
			rv = "TDDL_E_ALREADY_CLOSED";
			break;
		case TDDL_E_IOERROR:
			rv = "TDDL_E_IOERROR	";
			break;
		case TDDL_E_COMMAND_ABORTED:
			rv = "TDDL_E_COMMAND_ABORTED";
			break;
		case TCS_E_FAIL:
			rv = "TCS_E_FAIL";
			break;
		case TCS_E_KEY_MISMATCH:
			rv = "TCS_E_KEY_MISMATCH";
			break;
		case TCS_E_KM_LOADFAILED:
			rv = "TCS_E_KM_LOADFAILED";
			break;
		case TCS_E_KEY_CONTEXT_RELOAD:
			rv = "TCS_E_KEY_CONTEXT_RELOAD";
			break;
		case TCS_E_INVALID_CONTEXTHANDLE:
			rv = "TCS_E_INVALID_CONTEXTHANDLE";
			break;
		case TCS_E_INVALID_KEYHANDLE:
			rv = "TCS_E_INVALID_KEYHANDLE";
			break;
		case TCS_E_INVALID_AUTHHANDLE:
			rv = "TCS_E_INVALID_AUTHHANDLE";
			break;
		case TCS_E_INVALID_AUTHSESSION:
			rv = "TCS_E_INVALID_AUTHSESSION";
			break;
		case TCS_E_INVALID_KEY:
			rv = "TCS_E_INVALID_KEY";
			break;
		case TCS_E_KEY_NOT_REGISTERED:
			rv = "TCS_E_KEY_NOT_REGISTERED";
			break;
		case TCS_E_KEY_ALREADY_REGISTERED:
			rv = "TCS_E_KEY_ALREADY_REGISTERED";
			break;
		case TSS_E_INVALID_OBJECT_TYPE:
			rv = "TSS_E_INVALID_OBJECT_TYPE";
			break;
		case TSS_E_INVALID_OBJECT_INIT_FLAG:
			rv = "TSS_E_INVALID_OBJECT_INIT_FLAG";
			break;
		case TSS_E_INVALID_HANDLE:
			rv = "TSS_E_INVALID_HANDLE";
			break;
		case TSS_E_NO_CONNECTION:
			rv = "TSS_E_NO_CONNECTION";
			break;
		case TSS_E_CONNECTION_FAILED:
			rv = "TSS_E_CONNECTION_FAILED";
			break;
		case TSS_E_CONNECTION_BROKEN:
			rv = "TSS_E_CONNECTION_BROKEN";
			break;
		case TSS_E_HASH_INVALID_ALG:
			rv = "TSS_E_HASH_INVALID_ALG";
			break;
		case TSS_E_HASH_INVALID_LENGTH:
			rv = "TSS_E_HASH_INVALID_LENGTH";
			break;
		case TSS_E_HASH_NO_DATA:
			rv = "TSS_E_HASH_NO_DATA";
			break;
		case TSS_E_SILENT_CONTEXT:
			rv = "TSS_E_SILENT_CONTEXT";
			break;
		case TSS_E_INVALID_ATTRIB_FLAG:
			rv = "TSS_E_INVALID_ATTRIB_FLAG";
			break;
		case TSS_E_INVALID_ATTRIB_SUBFLAG:
			rv = "TSS_E_INVALID_ATTRIB_SUBFLAG";
			break;
		case TSS_E_INVALID_ATTRIB_DATA:
			rv = "TSS_E_INVALID_ATTRIB_DATA";
			break;
		case TSS_E_NO_PCRS_SET:
			rv = "TSS_E_NO_PCRS_SET";
			break;
		case TSS_E_KEY_NOT_LOADED:
			rv = "TSS_E_KEY_NOT_LOADED";
			break;
		case TSS_E_KEY_NOT_SET:
			rv = "TSS_E_KEY_NOT_SET";
			break;
		case TSS_E_VALIDATION_FAILED:
			rv = "TSS_E_VALIDATION_FAILED";
			break;
		case TSS_E_TSP_AUTHREQUIRED:
			rv = "TSS_E_TSP_AUTHREQUIRED";
			break;
		case TSS_E_TSP_AUTH2REQUIRED:
			rv = "TSS_E_TSP_AUTH2REQUIRED";
			break;
		case TSS_E_TSP_AUTHFAIL:
			rv = "TSS_E_TSP_AUTHFAIL";
			break;
		case TSS_E_TSP_AUTH2FAIL:
			rv = "TSS_E_TSP_AUTH2FAIL";
			break;
		case TSS_E_KEY_NO_MIGRATION_POLICY:
			rv = "TSS_E_KEY_NO_MIGRATION_POLICY";
			break;
		case TSS_E_POLICY_NO_SECRET:
			rv = "TSS_E_POLICY_NO_SECRET";
			break;
		case TSS_E_INVALID_OBJ_ACCESS:
			rv = "TSS_E_INVALID_OBJ_ACCESS";
			break;
		case TSS_E_INVALID_ENCSCHEME:
			rv = "TSS_E_INVALID_ENCSCHEME";
			break;
		case TSS_E_INVALID_SIGSCHEME:
			rv = "TSS_E_INVALID_SIGSCHEME";
			break;
		case TSS_E_ENC_INVALID_LENGTH:
			rv = "TSS_E_ENC_INVALID_LENGTH";
			break;
		case TSS_E_ENC_NO_DATA:
			rv = "TSS_E_ENC_NO_DATA";
			break;
		case TSS_E_ENC_INVALID_TYPE:
			rv = "TSS_E_ENC_INVALID_TYPE";
			break;
		case TSS_E_INVALID_KEYUSAGE:
			rv = "TSS_E_INVALID_KEYUSAGE";
			break;
		case TSS_E_VERIFICATION_FAILED:
			rv = "TSS_E_VERIFICATION_FAILED";
			break;
		case TSS_E_HASH_NO_IDENTIFIER:
			rv = "TSS_E_HASH_NO_IDENTIFIER";
			break;
		case TCPA_AUTHFAIL:
			rv = "TCPA_AUTHFAIL";
			break;
		case TCPA_BADINDEX:
			rv = "TCPA_BADINDEX";
			break;
		case TCPA_BADPARAMETER:
			rv = "TCPA_BADPARAMETER";
			break;
		case TCPA_AUDITFAILURE:
			rv = "TCPA_AUDITFAILURE";
			break;
		case TCPA_CLEAR_DISABLED:
			rv = "TCPA_CLEAR_DISABLED";
			break;
		case TCPA_DEACTIVATED:
			rv = "TCPA_DEACTIVATED";
			break;
		case TCPA_DISABLED:
			rv = "TCPA_DISABLED";
			break;
		case TCPA_DISABLED_CMD:
			rv = "TCPA_DISABLED_CMD";
			break;
		case TCPA_FAIL:
			rv = "TCPA_FAIL";
			break;
		case TCPA_BAD_ORDINAL:
			rv = "TCPA_BAD_ORDINAL";
			break;
		case TCPA_INSTALL_DISABLED:
			rv = "TCPA_INSTALL_DISABLED";
			break;
		case TCPA_INVALID_KEYHANDLE:
			rv = "TCPA_INVALID_KEYHANDLE";
			break;
		case TCPA_KEYNOTFOUND:
			rv = "TCPA_KEYNOTFOUND";
			break;
		case TCPA_INAPPROPRIATE_ENC:
			rv = "TCPA_INAPPROPRIATE_ENC";
			break;
		case TCPA_MIGRATE_FAIL:
			rv = "TCPA_MIGRATE_FAIL";
			break;
		case TCPA_INVALID_PCR_INFO:
			rv = "TCPA_INVALID_PCR_INFO";
			break;
		case TCPA_NOSPACE:
			rv = "TCPA_NOSPACE";
			break;
		case TCPA_NOSRK:
			rv = "TCPA_NOSRK";
			break;
		case TCPA_NOTSEALED_BLOB:
			rv = "TCPA_NOTSEALED_BLOB";
			break;
		case TCPA_OWNER_SET:
			rv = "TCPA_OWNER_SET";
			break;
		case TCPA_RESOURCES:
			rv = "TCPA_RESOURCES";
			break;
		case TCPA_SHORTRANDOM:
			rv = "TCPA_SHORTRANDOM";
			break;
		case TCPA_SIZE:
			rv = "TCPA_SIZE";
			break;
		case TCPA_WRONGPCRVAL:
			rv = "TCPA_WRONGPCRVAL";
			break;
		case TCPA_BAD_PARAM_SIZE:
			rv = "TCPA_BAD_PARAM_SIZE";
			break;
		case TCPA_SHA_THREAD:
			rv = "TCPA_SHA_THREAD";
			break;
		case TCPA_SHA_ERROR:
			rv = "TCPA_SHA_ERROR";
			break;
		case TCPA_FAILEDSELFTEST:
			rv = "TCPA_FAILEDSELFTEST";
			break;
		case TCPA_AUTH2FAIL:
			rv = "TCPA_AUTH2FAIL";
			break;
		case TCPA_BADTAG:
			rv = "TCPA_BADTAG";
			break;
		case TCPA_IOERROR:
			rv = "TCPA_IOERROR";
			break;
		case TCPA_ENCRYPT_ERROR:
			rv = "TCPA_ENCRYPT_ERROR";
			break;
		case TCPA_DECRYPT_ERROR:
			rv = "TCPA_DECRYPT_ERROR";
			break;
		case TCPA_INVALID_AUTHHANDLE:
			rv = "TCPA_INVALID_AUTHHANDLE";
			break;
		case TCPA_NO_ENDORSEMENT:
			rv = "TCPA_NO_ENDORSEMENT";
			break;
		case TCPA_INVALID_KEYUSAGE:
			rv = "TCPA_INVALID_KEYUSAGE";
			break;
		case TCPA_WRONG_ENTITYTYPE:
			rv = "TCPA_WRONG_ENTITYTYPE";
			break;
		case TCPA_INVALID_POSTINIT:
			rv = "TCPA_INVALID_POSTINIT";
			break;
		case TCPA_INAPPRORIATE_SIG:
			rv = "TCPA_INAPPRORIATE_SIG";
			break;
		case TCPA_BAD_KEY_PROPERTY:
			rv = "TCPA_BAD_KEY_PROPERTY";
			break;
		case TCPA_BAD_MIGRATION:
			rv = "TCPA_BAD_MIGRATION";
			break;
		case TCPA_BAD_SCHEME:
			rv = "TCPA_BAD_SCHEME";
			break;
		case TCPA_BAD_DATASIZE:
			rv = "TCPA_BAD_DATASIZE";
			break;
		case TCPA_BAD_MODE:
			rv = "TCPA_BAD_MODE";
			break;
		case TCPA_BAD_PRESENCE:
			rv = "TCPA_BAD_PRESENCE";
			break;
		case TCPA_BAD_VERSION:
			rv = "TCPA_BAD_VERSION";
			break;
		case TCPA_RETRY:
			rv = "TCPA_RETRY";
			break;
		case 0x99:
			rv = "0x99";
			break;
		case 0x777:
			rv = "0x777 (unimplemented callback called)";
			break;
		case 0x999:
			rv = "0x999";
			break;
		case 0x998:
			rv = "0x998";
			break;
		default:
			rv = "UNKNOWN";
			break;
	}
	return rv;
}
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
	if (   ((result & TSS_ERROR_LAYER_MASK) == TSS_ERROR_LAYER_TPM) ||
		(result == TSS_E_INVALID_HANDLE) ||
		(result == TSS_E_INTERNAL_ERROR) ||
		(result == TSS_E_BAD_PARAMETER) ||
		(result == TSS_E_KEY_NO_MIGRATION_POLICY) ||
		(result == TSS_E_FAIL) ||
		(result == TSS_E_NOTIMPL) ||
		(result == TSS_E_PS_KEY_NOTFOUND) ||
		(result == TSS_E_KEY_ALREADY_REGISTERED) ||
		(result == TSS_E_CANCELLED) ||
		(result == TSS_E_TIMEOUT) ||
		(result == TSS_E_OUTOFMEMORY) ||
		(result == TSS_E_TPM_UNEXPECTED) ||
		(result == TSS_E_COMM_FAILURE) ||
		(result == TSS_E_TPM_UNSUPPORTED_FEATURE) ||
		(result == TSS_E_INVALID_OBJECT_TYPE) ||
		(result == TSS_E_INVALID_OBJECT_INIT_FLAG) ||
		(result == TSS_E_NO_CONNECTION) ||
		(result == TSS_E_CONNECTION_FAILED) ||
		(result == TSS_E_CONNECTION_BROKEN) ||
		(result == TSS_E_HASH_INVALID_ALG) ||
		(result == TSS_E_HASH_INVALID_LENGTH) ||
		(result == TSS_E_HASH_NO_DATA) ||
		(result == TSS_E_SILENT_CONTEXT) ||
		(result == TSS_E_INVALID_ATTRIB_FLAG) ||
		(result == TSS_E_INVALID_ATTRIB_SUBFLAG) ||
		(result == TSS_E_NO_PCRS_SET) ||
		(result == TSS_E_KEY_NOT_LOADED) ||
		(result == TSS_E_KEY_NOT_SET) ||
		(result == TSS_E_VALIDATION_FAILED) ||
		(result == TSS_E_TSP_AUTHREQUIRED) ||
		(result == TSS_E_TSP_AUTH2REQUIRED) ||
		(result == TSS_E_TSP_AUTHFAIL) ||
		(result == TSS_E_TSP_AUTH2FAIL) ||
		(result == TSS_E_KEY_NO_MIGRATION_POLICY) ||
		(result == TSS_E_POLICY_NO_SECRET) ||
		(result == TSS_E_INVALID_OBJ_ACCESS) ||
		(result == TSS_E_INVALID_ENCSCHEME) ||
		(result == TSS_E_INVALID_SIGSCHEME) ||
		(result == TSS_E_ENC_INVALID_LENGTH) ||
		(result == TSS_E_ENC_NO_DATA) ||
		(result == TSS_E_ENC_INVALID_TYPE) ||
		(result == TSS_E_INVALID_KEYUSAGE) ||
		(result == TSS_E_VERIFICATION_FAILED) ||
		(result == TSS_E_HASH_NO_IDENTIFIER) ||
		(result == TSS_SUCCESS))
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

UNICODE *srv = NULL;

UNICODE *
get_server(char *server_name)
{
	int rc;

	if (server_name == NULL)
		return NULL;

	srv = malloc((strlen(server_name) + 1) * sizeof(UNICODE));
	if (srv == NULL) {
		fprintf(stderr, "Failed to malloc space for the server name.");
		exit(19);
	}

	rc = mbstowcs(srv, server_name, strlen(server_name) + 1);
	if (rc == (size_t)(-1)) {
		fprintf(stderr, "failed to convert server %s to UNICODE.", server_name);
		exit(19);
	}

	return srv;
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

