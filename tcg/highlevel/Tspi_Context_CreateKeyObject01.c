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
 *	Tspi_Context_CreateKeyObject01.c
 *
 * DESCRIPTION
 *	This program tests the creation of the key object using various
 *	valid and invalid init flags and checks to make sure the correct
 *	return codes come back.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *
 *	Test:
 *		1: Create a valid default key obj, check SUCCESS
 *		2: Create a valid sha1 key obj, check SUCCESS
 *		3: Create a valid other key obj, check SUCCESS
 *		4: Create an ambiguous key obj with 2 types, check
 *		   TSS_E_INVALID_OBJECT_INIT_FLAG
 *		5: Create an ambiguous key obj with no type, check
 *		   TSS_E_INVALID_OBJECT_INIT_FLAG
 *
 *	Cleanup:
 *		Print errno log and/or timing stats if options given
 *
 * USAGE
 *      First parameter is --options
 *                         -v or --version
 *      Second parameter is the version of the test case to be run
 *      This test case is currently only implemented for v1.1
 *
 * HISTORY
 *	Kent Yoder, shpedoikal@gmail.com, 10/07/04
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include <tss/tss.h>
#include "../common/common.h"

TSS_FLAG key_types[] = {TSS_KEY_EMPTY_KEY, TSS_KEY_TYPE_STORAGE, TSS_KEY_TYPE_BIND, TSS_KEY_TYPE_LEGACY,
		      TSS_KEY_TYPE_SIGNING, TSS_KEY_TYPE_IDENTITY, TSS_KEY_TYPE_AUTHCHANGE,
		      TSS_KEY_TSP_SRK, TSS_KEY_DEFAULT};
int key_types_size = 9;

TSS_FLAG invalid_key_types[] = { (TSS_KEY_MIGRATABLE|TSS_KEY_NOT_MIGRATABLE),
				 (TSS_KEY_VOLATILE|TSS_KEY_NON_VOLATILE),
				 (TSS_KEY_AUTHORIZATION|TSS_KEY_NO_AUTHORIZATION),
				 (TSS_KEY_DEFAULT|TSS_KEY_TYPE_IDENTITY),
				 (TSS_KEY_SIZE_16384|TSS_KEY_SIZE_8192),
				 (TSS_KEY_TYPE_SIGNING|TSS_KEY_TYPE_BIND),
				 (TSS_KEY_TYPE_STORAGE|TSS_KEY_TYPE_IDENTITY),
				 (TSS_KEY_TSP_SRK|TSS_KEY_TYPE_AUTHCHANGE),
				 (TSS_KEY_EMPTY_KEY|TSS_KEY_SIZE_512) };
int invalid_key_types_size = 9;

int
main( int argc, char **argv )
{
	char			*version;

	version = parseArgs( argc, argv );
		// if it is not version 1.1, print error
	if( strcmp(version, "1.1") )
		print_wrongVersion();
	else
		main_v1_1();
}

int
main_v1_1( void )
{
	char			*function = "Tspi_Context_CreateObject";
	TSS_RESULT		result;
	TSS_HCONTEXT		hContext;
	TSS_HOBJECT		hObject;
	int i;

	print_begin_test( function );

		// Create Context
	result = Tspi_Context_Create( &hContext );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Create", result );
		print_error_exit( function, err_string(result) );
		exit( result );
	}

		// Connect to Context
	result = Tspi_Context_Connect( hContext, NULL );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Connect", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* ==== TEST 1 LOOP ==== */

	/* create each of the different types of keys, then destroy on success */
	for (i = 0; i < key_types_size; i++) {
		/* create a default key obj */
		result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
				key_types[i], &hObject);
		if ( result == TSS_SUCCESS )
		{
			print_success( function, result );

			result = Tspi_Context_CloseObject(hContext, hObject);
			if (result != TSS_SUCCESS)
			{
				print_error( "Tspi_Context_CreateObject", result );
				print_error_exit( function, err_string(result) );
				Tspi_Context_FreeMemory( hContext, NULL );
				Tspi_Context_Close( hContext );
				exit( result );
			}
		}
		else
		{
			print_error( "Tspi_Context_CreateObject", result );
			print_error_exit( function, err_string(result) );
		}
	}

	/* ==== TEST 2 LOOP ==== */

	/* test creating each of the different types of invalid keys */
	for (i = 0; i < invalid_key_types_size; i++) {
		result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
				invalid_key_types[i], &hObject);
		if ( result == TSS_E_INVALID_OBJECT_INIT_FLAG )
		{
			print_success( function, result );

		}
		else
		{
			if (result == TSS_SUCCESS)
				Tspi_Context_CloseObject(hContext, hObject);
			print_error( "Tspi_Context_CreateObject", result );
			print_error_exit( function, err_string(result) );
		}
	}

	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( 0 );
}
