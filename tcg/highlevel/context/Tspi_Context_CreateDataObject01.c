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
 *	Tspi_Context_CreateDataObject01.c
 *
 * DESCRIPTION
 *	This program tests the creation of the data object using various
 *	valid and invalid init flags and checks to make sure the correct
 *	return codes come back.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *
 *	Test:
 *		1: Create a valid data seal obj, check SUCCESS
 *		2: Create a valid data bind obj, check SUCCESS
 *		3: Create a valid data legacy obj, check SUCCESS
 *		4: Create an ambiguous data obj with 2 types, check
 *		   TSS_E_INVALID_OBJECT_INITFLAG
 *		5: Create an ambiguous policy obj with a valid type and a
 *		   flag that doesn't make sense for data objs, check
 *		   TSS_E_INVALID_OBJECT_INITFLAG
 *		5: Create an ambiguous data obj with no type, check
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
#include "common.h"

int
main( int argc, char **argv )
{
	char version;

	version = parseArgs( argc, argv );
	if (version)
		main_v1_1();
	else
		print_wrongVersion();
}

int
main_v1_1( void )
{
	char			*function = "Tspi_Context_CreateObject01";
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

	/* create a data seal */
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA,
					   TSS_ENCDATA_SEAL, &hObject);
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

	/* create a data bind */
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA,
					   TSS_ENCDATA_BIND, &hObject);
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

	/* ==== TEST 3 ==== */

	/* create a data legacy obj */
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA,
					   TSS_ENCDATA_LEGACY, &hObject);
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

	/* ==== TEST 4 ==== */

	/* create an ambiguous obj */
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA,
					   0xffffffef, &hObject);
	if ( TSS_ERROR_CODE(result) == TSS_E_INVALID_OBJECT_INITFLAG )
	{
		print_success( function, result );
	}
	else
	{
		if (result == TSS_SUCCESS)
			Tspi_Context_CloseObject(hContext, hObject);
		print_error( "Tspi_Context_CreateObject", result );
	}

	/* ==== TEST 5 ==== */

	/* create another ambiguous data obj */
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA,
					   0xff00eeff, &hObject);
	if ( TSS_ERROR_CODE(result) == TSS_E_INVALID_OBJECT_INITFLAG )
	{
		print_success( function, result );
	}
	else
	{
		if (result == TSS_SUCCESS)
			Tspi_Context_CloseObject(hContext, hObject);
		print_error( "Tspi_Context_CreateObject", result );
	}

	/* ==== TEST 6 ==== */

	/* create an obj with no init flags */
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA,
					   0, &hObject);
	if ( TSS_ERROR_CODE(result) == TSS_E_INVALID_OBJECT_INITFLAG )
	{
		print_success( function, result );
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
	exit( 0 );
}
