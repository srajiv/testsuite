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
 *	Tspi_PolicyChecking01.c
 *
 * DESCRIPTION
 *	Tspi_PolicyChecking will test whether or not the
 *		proper default settings for policies are
 *		assigned.
 *
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Get Default Policy
 *		Check Defaults (Get Attrib Uint32)
 *
 *	Test:
 *		Call Tspi_PolicyChecking then if it does not succeed
 *		Make sure that it returns the proper return codes
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
 *	Modified by Debora Velarde, dvelarde@us.ibm.com, 09/04.
 *	Kent Yoder, shpedoikal@gmail.com, 09/04
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include <tss/tss.h>
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
	char			*function = "Tspi_PolicyChecking01";
	char			*function1 = "Tspi_GetAttribUint32";
	TSS_RESULT		result;
	TSS_HPOLICY		hPolicy;
	TSS_HCONTEXT		hContext;
	TSS_HOBJECT		hObject;
	UINT32			ES, exitCode1;

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

		// get policy
	result = Tspi_Context_GetDefaultPolicy ( hContext, &hPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_GetDefaultPolicy", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

/* ################# CHECKING DEFAULTS ################### */

	result = Tspi_GetAttribUint32( hPolicy,
					TSS_TSPATTRIB_POLICY_CALLBACK_HMAC,
					0, &ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode1 = 1;
	}
	else
	{
		if( ES != 0 )
		{
			print_error( function1, result );
			exitCode1 = 1;
		}
		else
		{
			print_success( function1, result);
			exitCode1 = 0;
		}
	}
	fprintf( stderr, "\t\tAddress of callback hmac: %x\n", ES );

	result = Tspi_GetAttribUint32( hPolicy,
					TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC,
					0, &ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode1 = 1;
	}
	else
	{
		if( ES != 0 )
		{
			print_error( function1, result );
			exitCode1 = 1;
		}
		else
		{
			print_success( function1, result);
			exitCode1 = 0;
		}
	}
	fprintf( stderr, "\t\tAddress of callback xor enc: %x\n", ES );

	result = Tspi_GetAttribUint32( hPolicy,
				TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP,
				0, &ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode1 = 1;
	}
	else
	{
		if( ES != 0 )
		{
			print_error( function1, result );
			exitCode1 = 1;
		}
		else
		{
			print_success( function1, result);
			exitCode1 = 0;
		}
	}
	fprintf( stderr, "\t\tAddress of callback take ownership: %x\n", ES );

	result = Tspi_GetAttribUint32( hPolicy,
				TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM,
				0, &ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode1 = 1;
	}
	else
	{
		if( ES != 0 )
		{
			print_error( function1, result );
			exitCode1 = 1;
		}
		else
		{
			print_success( function1, result);
			exitCode1 = 0;
		}
	}
	fprintf( stderr, "\t\tAddress of callback change auth asym: %x\n", ES );

	result = Tspi_GetAttribUint32( hPolicy,
			TSS_TSPATTRIB_POLICY_SECRET_LIFETIME,
			TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS, &ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode1 = 1;
	}
	else
	{
		/* flag not set by default */
		if( ES == FALSE )
		{
			print_error( function1, result );
			exitCode1 = 1;
		}
		else
		{
			print_success( function1, result);
			exitCode1 = 0;
		}
	}
	fprintf( stderr, "\t\tFlag set in policy object?: %x\n", ES );
	
	if( exitCode1 == 0 )
		print_success( function, result );
	else
		print_error( function, result );


	result = Tspi_GetAttribUint32( hPolicy,
			TSS_TSPATTRIB_POLICY_SECRET_LIFETIME,
			TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER, &ES );
	/* TSS_TSPATTRIB_POLICY_SECRET_LIFETIME Not set by default so 
	   TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER should return error */
	if ( result == TSS_SUCCESS )
	{
		print_error( function1, result );
		fprintf( stderr, "\t\tCounter value: %x\n", ES );
		exitCode1 = 1;
	}
	else
	{
		print_success( function1, result); 
		exitCode1 = 0;
	}

	result = Tspi_GetAttribUint32( hPolicy,
			TSS_TSPATTRIB_POLICY_SECRET_LIFETIME,
			TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER, &ES );
	/* TSS_TSPATTRIB_POLICY_SECRET_LIFETIME Not set by default so 
	   TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER should return error */
	if ( result == TSS_SUCCESS )
	{
		print_error( function1, result );
		fprintf( stderr, "\t\tTime value in seconds: %x\n", ES );
		exitCode1 = 1;
	}
	else
	{
		print_success( function1, result );
		exitCode1 = 0;
	}

	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( exitCode1 );
}
