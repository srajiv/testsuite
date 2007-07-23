/*
 *
 *   Copyright (C) International Business Machines  Corp., 2007
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
 *	Tspi_TPM_SetStatus_TempDeactivated01.c
 *
 * DESCRIPTION
 *	This test will use Tspi_TPM_SetStatus to temporarily
 *	deactivate the TPM (requires reboot to re-activate).
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Get TPM Object
 *		Create Operator Policy Object
 *		Set Policy Secret
 *	Test:
 *		Call Tspi_TPM_SetStatus
 *		Print results
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
 *      Megan Schneider, mschnei@us.ibm.com, 6/04.
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
	if ( version == TESTSUITE_TEST_TSS_1_1 )
		main_v1_1( );
	else if ( version >= TESTSUITE_TEST_TSS_1_2 )
		main_v1_2( version );
	else
		print_wrongVersion( );
}

int
main_setstatus( char version )
{
	char			*function = "Tspi_TPM_SetStatus_TempDeactivated01";
	TSS_HCONTEXT		hContext;
	TSS_HKEY		hSRK;
	TSS_HTPM		hTPM;
	TSS_HPOLICY		hOwnerPolicy, hOperatorPolicy;
	TSS_RESULT		result;
	TSS_BOOL		state;

	print_begin_test( function );

	result = connect_load_all( &hContext, &hSRK, &hTPM );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Create", result );
		print_error_exit( function, err_string(result) );
		exit( result );
	}

	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_POLICY,
			TSS_POLICY_USAGE, &hOwnerPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Policy_SetSecret( hOwnerPolicy, TESTSUITE_OWNER_SECRET_MODE,
			TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Policy_AssignToObject( hOwnerPolicy, hTPM );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	if ( version >= TESTSUITE_TEST_TSS_1_2 ) {
		// Use Operator Authorization for 1.2 or higher
		result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_POLICY,
				TSS_POLICY_OPERATOR, &hOperatorPolicy );
		if ( result != TSS_SUCCESS )
		{
			print_error( "Tspi_Context_CreateObject", result );
			print_error_exit( function, err_string(result) );
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit( result );
		}

		result = Tspi_Policy_SetSecret( hOperatorPolicy, TESTSUITE_OPERATOR_SECRET_MODE,
				TESTSUITE_OPERATOR_SECRET_LEN, TESTSUITE_OPERATOR_SECRET );
		if ( result != TSS_SUCCESS )
		{
			print_error( "Tspi_Policy_SetSecret", result );
			print_error_exit( function, err_string(result) );
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit( result );
		}

		result = Tspi_Policy_AssignToObject( hOperatorPolicy, hTPM );
		if ( result != TSS_SUCCESS )
		{
			print_error( "Tspi_Policy_SetSecret", result );
			print_error_exit( function, err_string(result) );
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit( result );
		}
	}

		// SetTempDeactivated
	result = Tspi_TPM_SetStatus( hTPM, TSS_TPMSTATUS_SETTEMPDEACTIVATED, TRUE );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_TPM_SetStatus", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	print_success( function, result);
	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( 0 );
}

int
main_v1_1( )
{
	return main_setstatus(TESTSUITE_TEST_TSS_1_1);
}

int
main_v1_2( char version )
{
	return main_setstatus(TESTSUITE_TEST_TSS_1_2);
}

