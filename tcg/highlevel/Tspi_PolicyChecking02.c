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
 *	Tspi_PolicyChecking02.c
 *
 * DESCRIPTION
 *	Tspi_PolicyChecking will assign new settings to
 *		a policy, and check that they are properly set.
 *
 *	Current issues with this test:
 *		- Lifetime Always flag does not stay set
 *		- Lifetime Timer flag is not implemented
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Get Default Policy
 *
 *	Test:
 *		Set Values (Set Attrib Uint32)
 *		Check Values (Get Attrib Uint32)
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
	char			*function = "Tspi_PolicyChecking02";
	char			*function1 = "Tspi_GetAttribUint32";
	char			*function2 = "Tspi_SetAttribUint32";
	TSS_RESULT		result;
	TSS_HPOLICY		hPolicy;
	TSS_HCONTEXT		hContext;
	TSS_HOBJECT		hObject;
	UINT32			exitCode1;
	UINT32			ES, ES1, ES2, ES3, ES4;
	const UINT32		ON = 1;
	const UINT32		OFF = 0;
	UINT32			lifetimeCounter =  5;
	UINT32			lifetimeTimer = 60;

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

/* ################# SETTING VALUES ################### */

	result = Tspi_SetAttribUint32( hPolicy,
					TSS_TSPATTRIB_POLICY_CALLBACK_HMAC,
					0, ES1 );
	if ( result != TSS_SUCCESS )
	{
		print_error( function2, result );
		exitCode1 = 1;
	}
	else
	{
		if( ES1 == 0 )
		{
			print_error( function2, result );
			exitCode1 = 1;
		}
		else
		{
			print_success( function2, result);
			exitCode1 = 0;
		}
	}
	fprintf( stderr, "\t\tAddress of callback hmac: %x\n", ES1 );

	result = Tspi_SetAttribUint32( hPolicy,
					TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC,
					0, ES2 );
	if ( result != TSS_SUCCESS )
	{
		print_error( function2, result );
		exitCode1 = 1;
	}
	else
	{
		if( ES2 == 0 )
		{
			print_error( function2, result );
			exitCode1 = 1;
		}
		else
		{
			print_success( function2, result);
			exitCode1 = 0;
		}
	}
	fprintf( stderr, "\t\tAddress of callback xor enc: %x\n", ES2 );

	result = Tspi_SetAttribUint32( hPolicy,
				TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP,
				0, ES3 );
	if ( result != TSS_SUCCESS )
	{
		print_error( function2, result );
		exitCode1 = 1;
	}
	else
	{
		if( ES3 == 0 )
		{
			print_error( function2, result );
			exitCode1 = 1;
		}
		else
		{
			print_success( function2, result);
			exitCode1 = 0;
		}
	}
	fprintf( stderr, "\t\tAddress of callback take ownership: %x\n", ES3 );

	result = Tspi_SetAttribUint32( hPolicy,
				TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM,
				0, ES4 );
	if ( result != TSS_SUCCESS )
	{
		print_error( function2, result );
		exitCode1 = 1;
	}
	else
	{
		if( ES4 == 0 )
		{
			print_error( function2, result );
			exitCode1 = 1;
		}
		else
		{
			print_success( function2, result);
			exitCode1 = 0;
		}
	}
	fprintf( stderr, "\t\tAddress of callback change auth asym: %x\n",
		ES4 );
#if 0
	result = Tspi_SetAttribUint32( hPolicy,
			TSS_TSPATTRIB_POLICY_SECRET_LIFETIME,
			TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS, ON );
	if ( result != TSS_SUCCESS )
	{
		print_error( function2, result );
		exitCode1 = 1;
	}
	else
	{
		if( ON == 0 )
		{
			print_error( function2, result );
			exitCode1 = 1;
		}
		else
		{
			print_success( function2, result);
			exitCode1 = 0;
		}
	}
	fprintf( stderr, "\t\tFlag set in policy object?: %x\n", ON );
#endif
	result = Tspi_SetAttribUint32( hPolicy,
			TSS_TSPATTRIB_POLICY_SECRET_LIFETIME,
			TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER, lifetimeCounter );
	if ( result != TSS_SUCCESS )
	{
		print_error( function2, result );
		exitCode1 = 1;
	}
	else
	{
		print_success( function2, result);
		exitCode1 = 0;
	}
	fprintf( stderr, "\t\tCounter value: %x\n", lifetimeCounter );

#if 0
	result = Tspi_SetAttribUint32( hPolicy,
			TSS_TSPATTRIB_POLICY_SECRET_LIFETIME,
			TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER, lifetimeTimer );
	if ( result != TSS_SUCCESS )
	{
		print_error( function2, result );
		exitCode1 = 1;
	}
	else
	{
		print_success( function2, result);
		exitCode1 = 0;
	}
	fprintf( stderr, "\t\tTime value in seconds: %x\n", lifetimeTimer );

	if( exitCode1 == 0 )
		print_success( function, result );
	else
		print_error( function, result );
#endif
	fprintf( stderr, "Done setting values. Checking values...\n" );

/* ###################### CHECKING VALUES ######################### */

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
		if( ES != ES1 )
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
		if( ES != ES2 )
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
		if( ES != ES3 )
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
		if( ES != ES4 )
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
	fprintf( stderr, "\t\tAddress of callback change auth asym: %x\n",
		ES );

#if 0
	result = Tspi_GetAttribUint32( hPolicy,
			TSS_TSPATTRIB_POLICY_SECRET_LIFETIME,
			TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS,
			&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode1 = 1;
	}
	else
	{
		if( ES != ON )
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
#endif

	result = Tspi_GetAttribUint32( hPolicy,
			TSS_TSPATTRIB_POLICY_SECRET_LIFETIME,
			TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER,
			&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode1 = 1;
	}
	else
	{
		if( ES != lifetimeCounter )
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
	fprintf( stderr, "\t\tCounter value: %x\n", ES );
#if 0
	result = Tspi_GetAttribUint32( hPolicy,
			TSS_TSPATTRIB_POLICY_SECRET_LIFETIME,
			TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER, &ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode1 = 1;
	}
	else
	{
		if( ES > lifetimeTimer )
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
	fprintf( stderr, "\t\tTime value in seconds: %x\n", ES );
#endif

	if( exitCode1 == 0 )
		print_success( function, result );
	else
		print_error( function, result );


	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( exitCode1 );
}
