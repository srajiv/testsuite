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
 *      common.h
 *
 * DESCRIPTION
 *      This file contains various defines, including those for
 *		error print statements. This file must be included
 *		for any current test case to run.
 *
 * ALGORITHM
 *      None.
 *
 * USAGE
 *      Include common.h in all test cases
 *
 * HISTORY
 *
 * RESTRICTIONS
 *      None.
 */

#ifndef _COMMON_H_
#define _COMMON_H_

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

char *err_string(TSS_RESULT);
char *parseArgs(int, char **);
void print_wrongVersion();
int checkNonAPI(TSS_RESULT);
void print_wrongChar();
void UINT32ToArray(UINT32 i, BYTE * out);
UNICODE * get_server(char *);
void print_hex(BYTE *, UINT32);

TSS_RESULT create_key(TSS_HCONTEXT, TSS_FLAG, TSS_HKEY, TSS_HKEY *);
TSS_RESULT create_load_key(TSS_HCONTEXT, TSS_FLAG, TSS_HKEY, TSS_HKEY *);
TSS_RESULT set_secret(TSS_HOBJECT, TSS_HPOLICY *);
TSS_RESULT connect_load_srk(TSS_HCONTEXT *, TSS_HKEY *);
TSS_RESULT connect_load_all(TSS_HCONTEXT *, TSS_HKEY *, TSS_HTPM *);
TSS_RESULT bind_and_unbind(TSS_HCONTEXT, TSS_HKEY);
TSS_RESULT sign_and_verify(TSS_HCONTEXT, TSS_HKEY);
TSS_RESULT seal_and_unseal(TSS_HCONTEXT, TSS_HKEY, TSS_HENCDATA, TSS_HPCRS);


int main_v1_1();

extern TSS_UUID SRK_UUID;

#define TESTSUITE_KEY_SECRET_MODE	TSS_SECRET_MODE_PLAIN
#define TESTSUITE_KEY_SECRET		"KEY PWD"
#define TESTSUITE_KEY_SECRET_LEN	strlen(TESTSUITE_KEY_SECRET)

#define TESTSUITE_NEW_SECRET_MODE	TSS_SECRET_MODE_PLAIN
#define TESTSUITE_NEW_SECRET		"NEW PWD"
#define TESTSUITE_NEW_SECRET_LEN	strlen(TESTSUITE_NEW_SECRET)

#define TESTSUITE_OWNER_SECRET_MODE	TSS_SECRET_MODE_PLAIN
#define TESTSUITE_OWNER_SECRET		getenv("TESTSUITE_OWNER_SECRET")
#define TESTSUITE_OWNER_SECRET_LEN	TESTSUITE_OWNER_SECRET == NULL ? 0 : strlen(TESTSUITE_OWNER_SECRET)

#define TESTSUITE_ENCDATA_SECRET_MODE	TSS_SECRET_MODE_PLAIN
#define TESTSUITE_ENCDATA_SECRET	"ENC PWD"
#define TESTSUITE_ENCDATA_SECRET_LEN	strlen(TESTSUITE_ENCDATA_SECRET)

#define TESTSUITE_SRK_SECRET_MODE	TSS_SECRET_MODE_PLAIN
#define TESTSUITE_SRK_SECRET		getenv("TESTSUITE_SRK_SECRET")
#define TESTSUITE_SRK_SECRET_LEN	TESTSUITE_SRK_SECRET == NULL ? 0 : strlen(TESTSUITE_SRK_SECRET)


#define print_error(function, result) \
	do { \
		printf("\t0 FAIL  :  %s  returned (%d) %s\n", function, result, err_string(result)); \
		fprintf(stderr, "\t0 FAIL  :  %s  returned (%d) %s\n", function, result, err_string(result));  \
	} while (0)

#define print_success(function, result) printf("\t1 PASS  :  %s  returned (%d) %s\n", function, result, err_string(result))

#define print_error_nonapi(function, result) \
	do { \
		printf("\t0 FAIL  :  %s  returned (%d) %s\n\t\t **This is not consistent with the API\n", function, result, err_string(result)); \
		fprintf(stderr, "\t0 FAIL  :  %s  returned (%d) %s\n", function, result, err_string(result));  \
	} while (0)

#define print_begin_test(function) printf("\n<<<test_start>>>\nTesting %s\n", function);
#define print_end_test(function) printf("Cleaning up %s\n<<<end_test>>>\n", function);
#define print_error_exit(function,errstr) printf("%s testing failed with %s\n", function, errstr);
#define print_verifyerr(string,expected,result) \
	fprintf(stderr, "Verifying " string " failed. Expected: 0x%x, got 0x%x\n", \
		expected, result);

/* use get_server as a generic UNICODE conversion routine */
#define char_to_unicode	Trspi_Native_To_UNICODE

#define GLOBALSERVER	NULL

#define TSS_ERROR_CODE(x)	(x & 0xFFF)
#define TSS_ERROR_LAYER(x)	(x & 0x3000)

#define NULL_HOBJECT	0
#define NULL_HKEY	NULL_HOBJECT
#define NULL_HPCRS	NULL_HOBJECT
#define NULL_HHASH	NULL_HOBJECT
#define NULL_HENCDATA	NULL_HOBJECT
#define NULL_HTPM	NULL_HOBJECT
#define NULL_HCONTEXT	NULL_HOBJECT

#endif
