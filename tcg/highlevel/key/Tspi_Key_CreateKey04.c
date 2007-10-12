/*
 *
 *   Copyright (C) International Business Machines  Corp., 2005
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2.
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


#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include "common.h"

#define TSS_KEY_TYPE_MASK       0x000000F0
#define TSS_KEY_TYPE(x)         (x & TSS_KEY_TYPE_MASK)


static struct option long_options[] = {
	{"enc-scheme", 1, 0, 'e'},
	{"sig-scheme", 1, 0, 'q'},
	{"key-size", 1, 0, 's'},
	{"auth", 0, 0, 'a'},
	{"volatile", 0, 0, 'v'},
	{"migratable", 0, 0, 'm'},
	{"type", 1, 0, 't'},
	{"popup", 0, 0, 'p'},
	{0, 0, 0, 0}
};

void
usage(char *argv0)
{
	fprintf(stderr, "\t%s: create a TPM key and write it to disk\n"
		"\tusage: %s [options] <filename>\n\n"
		"\tOptions:\n"
		"\t\t-e|--enc-scheme\tencryption scheme to use (PKCSV15, OAEP)\n"
		"\t\t-q|--sig-scheme\tsignature scheme to use (DER, SHA1)\n"
		"\t\t-s|--key-size\tkey size in bits (512, 1024, 2048, 4096, 8192, 16384)\n"
		"\t\t-v|--volatile\tkey should be volatile\n"
		"\t\t-m|--migratable\tkey should be migratable\n"
		"\t\t-t|--type\tkey type (Legacy, Signing, Storage or Bind)\n"
		"\t\t-a|--auth\trequire a password for the key\n"
		"\t\t-p|--popup\tuse TSS GUI popup dialogs to get the password "
		"for the\n\t\t\t\tkey (implies --auth)\n",
		argv0, argv0);
	exit(-1);
}

int
main(int argc, char **argv)
{
	TSS_HCONTEXT	hContext;
	TSS_FLAG	initFlags = 0;
	TSS_HKEY	hKey;
	TSS_HKEY	hSRK;
	TSS_RESULT	result;
	TSS_HPOLICY	keyUsagePolicy;
	char		c, *nameOfFunction = "Tspi_Key_CreateKey04";
	int		option_index, auth = 0, popup = 0;
	UINT32		enc_scheme = 0, sig_scheme = 0;
	UINT32		key_size = 0;

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "vmt:pe:q:s:a",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'a':
				initFlags |= TSS_KEY_AUTHORIZATION;
				auth = 1;
				break;
			case 'h':
				usage(argv[0]);
				break;
			case 's':
				key_size = atoi(optarg);
				break;
			case 'e':
				if (!strncasecmp("oaep", optarg, 4)) {
					enc_scheme = TSS_ES_RSAESOAEP_SHA1_MGF1;
				} else if (strncasecmp("pkcs", optarg, 4)) {
					usage(argv[0]);
				}
				break;
			case 'v':
				initFlags |= TSS_KEY_VOLATILE;
				break;
			case 'm':
				initFlags |= TSS_KEY_MIGRATABLE;
				break;
			case 't':
				if (!strncasecmp(optarg, "b", 1)) {
					initFlags |= TSS_KEY_TYPE_BIND;
				} else if (!strncasecmp(optarg, "l", 1)) {
					initFlags |= TSS_KEY_TYPE_LEGACY;
				} else if (!strncasecmp(optarg, "st", 2)) {
					initFlags |= TSS_KEY_TYPE_STORAGE;
				} else if (!strncasecmp(optarg, "si", 2)) {
					initFlags |= TSS_KEY_TYPE_SIGNING;
				} else {
					usage(argv[0]);
				}
				break;
			case 'q':
				if (!strncasecmp("der", optarg, 3)) {
					sig_scheme = TSS_SS_RSASSAPKCS1V15_SHA1;
				} else if (strncasecmp("sha", optarg, 3)) {
					usage(argv[0]);
				}
				break;
			case 'p':
				initFlags |= TSS_KEY_AUTHORIZATION;
				auth = 1;
				popup = 1;
				break;
			default:
				usage(argv[0]);
				break;
		}
	}

	if (TSS_KEY_TYPE(initFlags) == 0)
		usage(argv[0]);

	/* set up the key option flags */
	switch (key_size) {
		case 512:
			initFlags |= TSS_KEY_SIZE_512;
			break;
		case 1024:
			initFlags |= TSS_KEY_SIZE_1024;
			break;
		case 2048:
			initFlags |= TSS_KEY_SIZE_2048;
			break;
		case 4096:
			initFlags |= TSS_KEY_SIZE_4096;
			break;
		case 8192:
			initFlags |= TSS_KEY_SIZE_8192;
			break;
		case 16384:
			initFlags |= TSS_KEY_SIZE_16384;
			break;
		default:
			usage(argv[0]);
			break;
	}

	print_begin_test(nameOfFunction);

		//Create Context
	if ((result = connect_load_srk(&hContext, &hSRK))) {
		print_error("connect_load_srk", result);
		exit(result);
	}

		//Create Object
	if ((result = Tspi_Context_CreateObject(hContext,
						TSS_OBJECT_TYPE_RSAKEY,
						initFlags, &hKey))) {
		print_error("Tspi_Context_CreateObject", result);
		goto err;
	}

	if (sig_scheme) {
		if ((result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
						TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
						sig_scheme))) {
			print_error("Tspi_SetAttribUint32", result);
			goto err;
		}
	}

	if (enc_scheme) {
		if ((result = Tspi_SetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO,
						TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
						enc_scheme))) {
			print_error("Tspi_SetAttribUint32", result);
			goto err;
		}
	}

	if (auth) {
		//Get Policy Object
		if ((result = Tspi_GetPolicyObject(hKey, TSS_POLICY_USAGE,
						   &keyUsagePolicy))) {
			print_error("Tspi_GetPolicyObject", result);
			goto err;
		}

		if (popup) {
			//Set Secret
			if ((result = Tspi_Policy_SetSecret(keyUsagePolicy,
							    TSS_SECRET_MODE_POPUP,
							    0, NULL))) {
				print_error("Tspi_Policy_SetSecret", result);
				goto err;
			}
		} else {
			BYTE authdata[20] = { 1, 2, 3, 4, 5, 0, 9, 8, 7, 6,
					      1, 2, 3, 4, 5, 0, 9, 8, 7, 6 };

			//Set Secret
			if ((result = Tspi_Policy_SetSecret(keyUsagePolicy,
							    TSS_SECRET_MODE_SHA1,
							    20, authdata))) {
				print_error("Tspi_Policy_SetSecret", result);
				free(authdata);
				goto err;
			}
		}
	}

		//Create Key
	if ((result = Tspi_Key_CreateKey(hKey, hSRK, 0))) {
		print_error("Tspi_Key_CreateKey", result);
		goto err;
	}

		//Load Key
	if ((result = Tspi_Key_LoadKey(hKey, hSRK))) {
		print_error("Tspi_Key_LoadKey", result);
		goto err;
	}

	Tspi_Context_Close(hContext);
	print_success(nameOfFunction, result);
	print_end_test(nameOfFunction);

	return 0;

err:
	print_error(nameOfFunction, result);
	Tspi_Context_Close(hContext);
	exit(result);
}
