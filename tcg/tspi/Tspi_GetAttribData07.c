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
 *	Tspi_GetAttribData07.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_GetAttribData.
 *	The purpose of this test case is to get TSS_E_INVALID_HANDLE to 
 *		be returned. This is easily accomplished by only calling
 *		Tspi_GetAttribData without setting anything up.
 *
 * ALGORITHM
 *	Setup:	None
 *
 *	Test:	Call GetAttribData. If it is not a success
 *		Make sure that it returns the proper return codes
 *
 *	Cleanup:
 *		Print error/success message
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
	char		*nameOfFunction = "Tspi_GetAttribData07";
	TSS_HKEY	hKey;
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	BYTE*		BLOB;
	UINT32		BlobLength;

	print_begin_test(nameOfFunction);

		//Call GetAttribData
	result = Tspi_GetAttribData(hKey,
			TSS_TSPATTRIB_KEY_BLOB,
			TSS_TSPATTRIB_KEYBLOB_BLOB,
			&BlobLength, &BLOB);
	if (TSS_ERROR_CODE(result) != TSS_E_INVALID_HANDLE) {
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			exit(result);
		}
		else{
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			exit(result);
		}
	}
	else{
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		exit(0);
	}
}
