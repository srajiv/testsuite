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
 *	Tspi_TPM_StatusTest02.c
 *
 * DESCRIPTION
 *	This test will use Tspi_TPM_SetStatus to show that
 *		each key has the proper default flags.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Get TPM Object
 *		Get Policy Object
 *		Set Status
 *	Test:
 *		Call Tspi_TPM_SetStatus
 *		Make sure that all keys are shown as registered
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
	if (version)
		main_v1_1();
	else
		print_wrongVersion();
}

int
main_v1_1( void )
{
	char			*function = "Tspi_TPM_StatusTest02";
	char			*function1 = "Tspi_TPM_SetStatus";
	char			*function2 = "Tspi_TPM_GetStatus";
	TSS_HKEY		hParentKey;
	TSS_HTPM		hTPM;
	TSS_HPOLICY		hPolicy;
	TSS_RESULT		result;
	TSS_BOOL		state;
	TSS_HCONTEXT		hContext;
	int			exitCode, value01, value02, tempFlag;
	TSS_FLAG		initFlags = TSS_KEY_TYPE_SIGNING |
						TSS_KEY_SIZE_2048 |
						TSS_KEY_VOLATILE |
						TSS_KEY_NO_AUTHORIZATION |
						TSS_KEY_NOT_MIGRATABLE;

	print_begin_test( function );
	srand( time(0) );
	tempFlag = rand() % 10;

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

	result = Tspi_Context_GetTpmObject( hContext, &hTPM );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_GetTpmObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );

	}

	result = Tspi_GetPolicyObject( hTPM, TSS_POLICY_USAGE, &hPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Policy_SetSecret( hPolicy, TESTSUITE_OWNER_SECRET_MODE,
					TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}


/* ###################### Set Status ####################### */

	result = Tspi_TPM_SetStatus( hTPM,
					TSS_TPMSTATUS_DISABLEOWNERCLEAR,
					FALSE );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		result = Tspi_TPM_GetStatus( hTPM,
					TSS_TPMSTATUS_DISABLEOWNERCLEAR,
					&state );
		if ( result != TSS_SUCCESS )
		{
			print_error( function2, result );
			exitCode = 1;
		}
		else
		{
			if( state == 0 )
			{
				print_error( function1, result );
				exitCode = 1;
			}
			else
			{
				print_success( function1, result);
				exitCode = 0;
			}
		}
	}
	fprintf( stderr, "\t\tDisable Owner Clear: %x\n", state );

	result = Tspi_TPM_SetStatus( hTPM,
					TSS_TPMSTATUS_DISABLEFORCECLEAR,
					TRUE );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		result = Tspi_TPM_GetStatus( hTPM,
					TSS_TPMSTATUS_DISABLEFORCECLEAR,
					&state );
		if ( result != TSS_SUCCESS )
		{
			print_error( function2, result );
			exitCode = 1;
		}
		else
		{
			if( state == 0 )
			{
				print_error( function1, result );
				exitCode = 1;
			}
			else
			{
				print_success( function1, result);
				exitCode = 0;
			}
		}
	}
	fprintf( stderr, "\t\tDisable Force Clear: %x\n", state );

	result = Tspi_TPM_SetStatus( hTPM,
					TSS_TPMSTATUS_SETTEMPDEACTIVATED,
					TRUE );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		result = Tspi_TPM_GetStatus( hTPM,
					TSS_TPMSTATUS_SETTEMPDEACTIVATED,
					&state );
		if ( result != TSS_SUCCESS )
		{
			print_error( function2, result );
			exitCode = 1;
		}
		else
		{
			if( state == 0 )
			{
				print_error( function1, result );
				exitCode = 1;
			}
			else
			{
				print_success( function1, result);
				exitCode = 0;
			}
		}
	}
	fprintf( stderr, "\t\tSet Temp Deactivated: %x\n", state );

	result = Tspi_TPM_SetStatus( hTPM,
					TSS_TPMSTATUS_SETOWNERINSTALL,
					TRUE );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		result = Tspi_TPM_GetStatus( hTPM,
					TSS_TPMSTATUS_SETOWNERINSTALL,
					&state );
		if ( result != TSS_SUCCESS )
		{
			print_error( function2, result );
			exitCode = 1;
		}
		else
		{
			if( state == 0 )
			{
				print_error( function1, result );
				exitCode = 1;
			}
			else
			{
				print_success( function1, result);
				exitCode = 0;
			}
		}
	}
	fprintf( stderr, "\t\tSet Owner Install: %x\n", state );

	result = Tspi_TPM_SetStatus( hTPM,
					TSS_TPMSTATUS_DISABLEPUBEKREAD,
					TRUE );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		result = Tspi_TPM_GetStatus( hTPM,
					TSS_TPMSTATUS_DISABLEPUBEKREAD,
					&state );
		if ( result != TSS_SUCCESS )
		{
			print_error( function2, result );
			exitCode = 1;
		}
		else
		{
			if( state == 0 )
			{
				print_error( function1, result );
				exitCode = 1;
			}
			else
			{
				print_success( function1, result);
				exitCode = 0;
			}
		}
	}
	fprintf( stderr, "\t\tDisable pub key read: %x\n", state );

	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( exitCode );
}
