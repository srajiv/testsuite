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
 *	Tspi_TPM_GetStatus04.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_TPM_GetStatus
 *		returns TSS_SUCCESS.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Get TPM Object
 *		Get Policy Object
 *		Set Secret
 *
 *	Test:
 *		Call TPM_GetStatus then if it does not succeed
 *		Make sure that it returns the proper return codes
 *		Print results
 *
 *	Cleanup:
 *		Free memory relating to hContext
 *		Close context
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

struct status_flag {
	char *flag;
	TSS_FLAG value;
};

struct status_flag status_flags[] = {
	{ "     TSS_TPMSTATUS_DISABLEOWNERCLEAR", TSS_TPMSTATUS_DISABLEOWNERCLEAR },
        { "     TSS_TPMSTATUS_DISABLEFORCECLEAR", TSS_TPMSTATUS_DISABLEFORCECLEAR },
        { "              TSS_TPMSTATUS_DISABLED", TSS_TPMSTATUS_DISABLED },
        { "TSS_TPMSTATUS_PHYSICALSETDEACTIVATED", TSS_TPMSTATUS_PHYSICALSETDEACTIVATED },
        { "    TSS_TPMSTATUS_SETTEMPDEACTIVATED", TSS_TPMSTATUS_SETTEMPDEACTIVATED },
        { "       TSS_TPMSTATUS_SETOWNERINSTALL", TSS_TPMSTATUS_SETOWNERINSTALL },
        { "      TSS_TPMSTATUS_DISABLEPUBEKREAD", TSS_TPMSTATUS_DISABLEPUBEKREAD },
        { "      TSS_TPMSTATUS_ALLOWMAINTENANCE", TSS_TPMSTATUS_ALLOWMAINTENANCE },
        { " TSS_TPMSTATUS_PHYSPRES_LIFETIMELOCK", TSS_TPMSTATUS_PHYSPRES_LIFETIMELOCK },
        { "     TSS_TPMSTATUS_PHYSPRES_HWENABLE", TSS_TPMSTATUS_PHYSPRES_HWENABLE },
        { "    TSS_TPMSTATUS_PHYSPRES_CMDENABLE", TSS_TPMSTATUS_PHYSPRES_CMDENABLE },
        { "             TSS_TPMSTATUS_CEKP_USED", TSS_TPMSTATUS_CEKP_USED },
        { "          TSS_TPMSTATUS_PHYSPRESENCE", TSS_TPMSTATUS_PHYSPRESENCE },
	{ "         TSS_TPMSTATUS_PHYSPRES_LOCK", TSS_TPMSTATUS_PHYSPRES_LOCK },
	{ "", 0 }
};

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
	char			*function = "Tspi_TPM_GetStatus04";
	TSS_HCONTEXT		hContext;
	TSS_HTPM		hTPM;
	TSS_HPOLICY		hPolicy;
	TSS_BOOL			state;
	TSS_RESULT		result;
	UINT32			exitCode, i;

	print_begin_test( function );

		// Create Context
	result = Tspi_Context_Create( &hContext );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Create", result );
		exit( result );
	}

		// Connect to Context
	result = Tspi_Context_Connect( hContext, get_server(GLOBALSERVER) );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Connect", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// Retrieve TPM object of context
	result = Tspi_Context_GetTpmObject( hContext, &hTPM );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_GetTpmObject", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_GetPolicyObject( hTPM, TSS_POLICY_USAGE, &hPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Policy_SetSecret( hPolicy, TESTSUITE_OWNER_SECRET_MODE,
					TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	i = 0;
	while (status_flags[i].value != 0) {
		result = Tspi_TPM_GetStatus( hTPM, status_flags[i].value, &state );

		if (!result) {
			printf("%s: %s\n", status_flags[i].flag, state ? "TRUE" : "FALSE");
			i++;
		} else {
			break;
		}
	}
	if ( result != TSS_SUCCESS )
	{
		if( !(checkNonAPI(result)) )
		{
			print_error( function, result );
			exitCode = 1;
		}
		else
		{
			print_error_nonapi( function, result );
			exitCode = 1;
		}
	}
	else
	{
		print_success( function, result );
		exitCode = 0;
	}

	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( exitCode );
}
