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
 *	Tspi_GetAttribUint3203.c
 *
 * DESCRIPTION
 *	This test will return TSS_E_INVALID_ATTRIB_FLAG for the
 *		first several Tspi_GetAttribUint32 calls, because:
 *			- a subflag is passed as the main flag.
 *			- a non-flag (key type) is passed as a flag.
 *			- a non-policy flag is passed for a policy
 *				object.
 *	This test will also return TSS_E_INVALID_ATTRIB_SUBFLAG for
 *		the second Tspi_GetAttribUint32 call, because:
 *			- a non-policy subflag is passed as a subflag.
 *			- a non-context subflag is passed as a subflag.
 *			- a subflag that does not match the main flag is
 *				passed as a subflag. (twice)
 *			- a main flag is passed as a subflag.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Create Object
 *		Create Object
 *
 *	Test:
 *		Call Tspi_GetAttribUint32 twice then if it does not succeed
 *		Make sure that it returns the proper return codes
 *		Print results
 *
 *	Cleanup:
 *		Free memory related to hContext
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
	char			*function = "Tspi_GetAttribUint3203";
	TSS_HKEY		hParentKey;
	TSS_HPOLICY		hPolicy;
	TSS_HCONTEXT		hContext;
	UINT32			ES;
	UINT32			SS;
	TSS_RESULT		result;
	UINT32			exitCode;
	TSS_FLAGS		initFlags = TSS_KEY_TYPE_SIGNING |
						TSS_KEY_SIZE_2048 |
						TSS_KEY_VOLATILE |
						TSS_KEY_NO_AUTHORIZATION |
						TSS_KEY_NOT_MIGRATABLE;

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

		// Create and initialize empty object
	result = Tspi_Context_CreateObject( hContext,
						TSS_OBJECT_TYPE_RSAKEY,
						initFlags, &hParentKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (parent key)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_CreateObject( hContext,
						TSS_OBJECT_TYPE_POLICY,
						TSS_POLICY_USAGE, &hPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (parent key)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_GetAttribUint32( hParentKey,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					&ES );
	if ( result != TSS_E_INVALID_ATTRIB_FLAG )
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

	result = Tspi_GetAttribUint32( hContext,
					TSS_KEY_SIZE_1024,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					&ES );
	if ( result != TSS_E_INVALID_ATTRIB_FLAG )
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
	}

	result = Tspi_GetAttribUint32( hPolicy,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					&ES );
	if ( result != TSS_E_INVALID_ATTRIB_FLAG )
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
	}

	result = Tspi_GetAttribUint32( hPolicy,
					TSS_TSPATTRIB_POLICY_SECRET_LIFETIME,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					&ES );
	if ( result != TSS_E_INVALID_ATTRIB_SUBFLAG )
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
	}

	result = Tspi_GetAttribUint32( hContext,
					TSS_TSPATTRIB_CONTEXT_SILENT_MODE,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					&ES );
	if ( result != TSS_E_INVALID_ATTRIB_SUBFLAG )
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
	}

	result = Tspi_GetAttribUint32( hParentKey,
					TSS_TSPATTRIB_KEY_REGISTER,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					&ES );
	if ( result != TSS_E_INVALID_ATTRIB_SUBFLAG )
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
	}

	result = Tspi_GetAttribUint32( hParentKey,
					TSS_TSPATTRIB_RSAKEY_INFO,
					0xffffffff,
					&ES );
	if ( result != TSS_E_INVALID_ATTRIB_SUBFLAG )
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
	}

		// Set uint, key sig scheme
	result = Tspi_GetAttribUint32( hParentKey,
					TSS_TSPATTRIB_KEY_INFO,
					0xffffffff,
					&SS );
	if ( result != TSS_E_INVALID_ATTRIB_SUBFLAG )
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
	}

	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( exitCode );
}
