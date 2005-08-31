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
#define get_server(s)	(UNICODE *)Trspi_UTF8_To_UNICODE(s, NULL)
void print_hex(BYTE *, UINT32);

TSS_RESULT create_key(TSS_HCONTEXT, TSS_FLAG, TSS_HKEY, TSS_HKEY *);
TSS_RESULT create_load_key(TSS_HCONTEXT, TSS_FLAG, TSS_HKEY, TSS_HKEY *);
TSS_RESULT set_secret(TSS_HOBJECT, TSS_HPOLICY *);
TSS_RESULT connect_load_srk(TSS_HCONTEXT *, TSS_HKEY *);
TSS_RESULT connect_load_all(TSS_HCONTEXT *, TSS_HKEY *, TSS_HTPM *);


int main_v1_1();

extern TSS_UUID SRK_UUID;

#if 0
/* uuids for use in test cases */
TSS_UUID uuid1 = {1,2,4,8,6,{2,4,8,2,4,8}};
TSS_UUID uuid2 = {1,3,6,9,7,{3,6,9,3,6,9}};
TSS_UUID uuid3 = {1,5,2,6,3,{7,4,8,5,9,6}};
TSS_UUID uuid4 = {2,4,6,8,2,{4,6,8,3,2,1}};
TSS_UUID uuid5 = {9,1,8,2,7,{3,6,4,5,5,4}};
TSS_UUID uuid6 = {3,1,4,1,5,{9,2,6,5,3,5}};
TSS_UUID uuid7 = {2,7,1,8,2,{8,1,8,2,8,5}};
TSS_UUID uuid8 = {1,7,3,2,0,{5,0,8,0,7,5}};
TSS_UUID uuid9 = {1,4,1,4,2,{1,3,5,6,2,3}};
TSS_UUID uuid0 = {2,3,5,7,5,{1,9,9,2,7,3}};
#endif

/* Storage root key password */
#define KEY_PWD		"KEY PWD"
#define NEW_PWD		"NEW PWD"
#define OWN_PWD		"OWN PWD"
#define ENCDATA_PWD	"ENC PWD"

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
#define print_error_exit(function,result) printf("%s testing failed with %s\n", function, result);

/* use get_server as a generic UNICODE conversion routine */
#define char_to_unicode	Trspi_UTF8_To_UNICODE

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
