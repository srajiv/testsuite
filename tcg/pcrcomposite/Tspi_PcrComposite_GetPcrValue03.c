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
 *	Tspi_PcrComposite_GetPcrValue03.c
 *
 * DESCRIPTION
 *	This test will return TSS_E_BAD_PARAMETER
 *		because -3 is passed in as the second parameter
 *		in PcrComposite_GetPcrValue, instead of 8
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Create PCR Composite
 *
 *	Test:
 *		Call PcrComposite_GetPcrValue then if it is not a success
 *		Call the Common Errors
 *		Make sure that it returns the proper return codes
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
 *      Megan Schneider, mschnei@us.ibm.com, 6/04.
 *      Kent Yoder, shpedoikal@gmail.com, 10/15/04
 *        Fixed object init flags
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include "common.h"


int
main( int argc, char **argv )
{
	char		*version;

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
	char		*function = "Tspi_PcrComposite_GetPcrValue03";
	TSS_HCONTEXT	hContext;
	TSS_HPCRS	hPcrComposite;
	BYTE		rgbPcrValueIn[20] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	BYTE		*prgbPcrValueOut;
	UINT32		ulPcrValueLength;
	TSS_RESULT	result;

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
	result = Tspi_Context_Connect( hContext, get_server(GLOBALSERVER) );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Connect", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// create object
	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_PCRS,
					0, &hPcrComposite );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (hPcrComposite)",
				result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// get pcr value
	result = Tspi_PcrComposite_GetPcrValue( hPcrComposite, 0xffff,
						&ulPcrValueLength,
						&prgbPcrValueOut );
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER )
	{
		if( !(checkNonAPI(result)) )
		{
			print_error( function, result );
			print_end_test( function );
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit(result);
		}
		else
		{
			print_error_nonapi( function, result );
			print_end_test( function );
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit(result);
		}
	}
	else
	{
		print_success( function, result );
	}

	result = Tspi_PcrComposite_GetPcrValue( hPcrComposite, 8,
						NULL,
						&prgbPcrValueOut );
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER )
	{
		if( (TSS_ERROR_CODE(result) == TSS_E_INVALID_HANDLE) ||
				(TSS_ERROR_CODE(result) == TSS_E_INTERNAL_ERROR) ||
				(result == TSS_SUCCESS) ||
				(TSS_ERROR_CODE(result) == TSS_E_FAIL) ||
				(TSS_ERROR_CODE(result) == TSS_E_NOTIMPL) ||
				(TSS_ERROR_CODE(result) == TSS_E_PS_KEY_NOTFOUND) ||
				(TSS_ERROR_CODE(result) == TSS_E_KEY_ALREADY_REGISTERED) ||
				(TSS_ERROR_CODE(result) == TSS_E_CANCELED) ||
				(TSS_ERROR_CODE(result) == TSS_E_TIMEOUT) ||
				(TSS_ERROR_CODE(result) == TSS_E_OUTOFMEMORY) ||
				(TSS_ERROR_CODE(result) == TSS_E_TPM_UNEXPECTED) ||
				(TSS_ERROR_CODE(result) == TSS_E_COMM_FAILURE) ||
				(TSS_ERROR_CODE(result) == TSS_E_TPM_UNSUPPORTED_FEATURE) )
		{
			print_error( function, result );
			print_end_test( function );
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit(result);
		}
		else
		{
			print_error_nonapi( function, result );
			print_end_test( function );
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit(result);
		}
	}
	else
	{
		print_success( function, result );
	}

	result = Tspi_PcrComposite_GetPcrValue( hPcrComposite, 20,
						&ulPcrValueLength,
						NULL );
	if ( TSS_ERROR_CODE(result) != TSS_E_BAD_PARAMETER )
	{
		if( (TSS_ERROR_CODE(result) == TSS_E_INVALID_HANDLE) ||
				(TSS_ERROR_CODE(result) == TSS_E_INTERNAL_ERROR) ||
				(result == TSS_SUCCESS) ||
				(TSS_ERROR_CODE(result) == TSS_E_FAIL) ||
				(TSS_ERROR_CODE(result) == TSS_E_NOTIMPL) ||
				(TSS_ERROR_CODE(result) == TSS_E_PS_KEY_NOTFOUND) ||
				(TSS_ERROR_CODE(result) == TSS_E_KEY_ALREADY_REGISTERED) ||
				(TSS_ERROR_CODE(result) == TSS_E_CANCELED) ||
				(TSS_ERROR_CODE(result) == TSS_E_TIMEOUT) ||
				(TSS_ERROR_CODE(result) == TSS_E_OUTOFMEMORY) ||
				(TSS_ERROR_CODE(result) == TSS_E_TPM_UNEXPECTED) ||
				(TSS_ERROR_CODE(result) == TSS_E_COMM_FAILURE) ||
				(TSS_ERROR_CODE(result) == TSS_E_TPM_UNSUPPORTED_FEATURE) )
		{
			print_error( function, result );
			print_end_test( function );
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit(result);
		}
		else
		{
			print_error_nonapi( function, result );
			print_end_test( function );
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit(result);
		}
	}
	else
	{
		print_success( function, result );
		print_end_test( function );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( 0 );
	}

}
