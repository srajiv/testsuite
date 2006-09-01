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
 *	Tspi_Context_CreatePcrsObject01.c
 *
 * DESCRIPTION
 *	This program tests the creation of the pcrs object using various
 *	valid and invalid init flags and checks to make sure the correct
 *	return codes come back.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *
 *	Test:
 *		1: Create a valid default pcrs obj, check SUCCESS
 *		2: Create a pcrs obj with some invalid type, check
 *		   TSS_E_INVALID_OBJECT_INITFLAG
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
#include <trousers/tss.h>
#include "../common/common.h"

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

	print_begin_test( function );

		// Create Context
	result = Tspi_Context_Create( &hContext );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Create", result );
		print_error_exit( function, err_string(result) );
		exit( result );
	}

	/* ==== TEST 1 ==== */

	/* create a valid pcrs obj */
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS,
					   0, &hObject);
	if ( result == TSS_SUCCESS )
	{
		print_success( function, result );
	}
	else
	{
		print_error( "Tspi_Context_CreateObject", result );
		print_error_exit( function, err_string(result) );
	}
	/* close the object, test done */
	result = Tspi_Context_CloseObject(hContext, hObject);
	if (result != TSS_SUCCESS)
	{
		print_error( "Tspi_Context_CreateObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* ==== TEST 2 ==== */

	/* create a pcrs obj with some bogus flag */
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS,
					   0xdeadbeef, &hObject);
	if ( TSS_ERROR_CODE(result) == TSS_E_INVALID_OBJECT_INITFLAG )
	{
		print_success( function, result );
		result = 0;
	}
	else
	{
		if (result == TSS_SUCCESS)
			Tspi_Context_CloseObject(hContext, hObject);
		print_error( "Tspi_Context_CreateObject", result );
	}

	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( result );
}
