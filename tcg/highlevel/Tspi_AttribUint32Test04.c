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
 *	Tspi_AttribUint32Test04.c
 *
 * DESCRIPTION
 *	This test will use Tspi_SetAttribUint32 to show that
 *		each key has the proper attributes (individual
 *		flags).
 *	hlsetup must be run prior to this test.
 *
 *	Current issues with this test:
 *		- unfinished
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Load 10 Keys
 *
 *	Test:
 *		Call Tspi_SetAttribUint32 then if it succeeds
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
#include <tss/tss.h>
#include "hlsetup.h"

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
	char			*function = "Tspi_AttribUint32Test04";
	char			*function1 = "Tspi_SetAttribUint32";
	TSS_HKEY		hParentKey;
	TSS_RESULT		result;
	UINT32			ES;
	int			exitCode, value01, value02, tempFlag;
	TSS_FLAGS		initFlags = TSS_KEY_TYPE_SIGNING |
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

	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						uuid0, &hKey0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hKey0)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						uuid1, &hKey1 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hKey1)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						uuid2, &hKey2 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hKey2)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						uuid3, &hKey3 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hKey3)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						uuid4, &hKey4 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hKey4)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						uuid5, &hKey5 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hKey5)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						uuid6, &hKey6 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hKey6)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						uuid7, &hKey7 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hKey7)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						uuid8, &hKey8 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hKey8)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						uuid9, &hKey9 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hKey9)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

/* ###################### Key 0 ####################### */

	fprintf( stderr, "Key O:\n" );

	result = Tspi_SetAttribUint32( hKey0,
					TSS_TSPATTRIB_KEY_REGISTER,
					0,
					TSS_TSPATTRIB_KEYREGISTER_USER );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}

	result = Tspi_SetAttribUint32( hKey0,
					TSS_TSPATTRIB_KEY_REGISTER,
					0,
					TSS_TSPATTRIB_KEYREGISTER_SYSTEM );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
	}

	result = Tspi_SetAttribUint32( hKey0,
					TSS_TSPATTRIB_KEY_REGISTER,
					0,
					TSS_TSPATTRIB_KEYREGISTER_NO );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
	}

		// get uint attrib
	result = Tspi_SetAttribUint32( hKey0,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_USAGE,
					TSS_KEYUSAGE_STORAGE );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
	}

	result = Tspi_SetAttribUint32( hKey0,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_MIGRATABLE,
					TRUE );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
	}

	result = Tspi_SetAttribUint32( hKey0,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_REDIRECTED,
					TRUE );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
	}

	result = Tspi_SetAttribUint32( hKey0,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_VOLATILE,
					TRUE );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
	}

	result = Tspi_SetAttribUint32( hKey0,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE,
					TRUE );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
	}

	result = Tspi_SetAttribUint32( hKey0,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ALGORITHM,
					TSS_ALG_3DES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
	}

/* ################# Key 1 ##################### */

	fprintf( stderr, "Key 1:\n" );

		// get uint attrib
	result = Tspi_SetAttribUint32( hKey1,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_USAGE,
					TSS_KEYUSAGE_STORAGE );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
	}

	result = Tspi_SetAttribUint32( hKey1,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_MIGRATABLE,
					FALSE );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
	}

	result = Tspi_SetAttribUint32( hKey1,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_REDIRECTED,
					FALSE );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
	}

	result = Tspi_SetAttribUint32( hKey1,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_VOLATILE,
					FALSE );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
	}

	result = Tspi_SetAttribUint32( hKey1,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE,
					FALSE );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
	}

	result = Tspi_SetAttribUint32( hKey1,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ALGORITHM,
					TSS_ALG_SHA );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
	}


// this needs to be finished along the same lines as above
#if 0
	result = Tspi_SetAttribUint32( hKey1,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_ES_RSAESOAEP_SHA1_MGF1 */
		if( ES != TSS_ES_RSAESOAEP_SHA1_MGF1 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tEncscheme (3=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey1,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_SS_NONE (no sig scheme) */
		if( ES != TSS_SS_NONE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tSigscheme (1=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey1,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_KEYFLAGS,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tKeyflags: %x\n", ES );

	result = Tspi_SetAttribUint32( hKey1,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHUSAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tAuthUsage: %x\n", ES );

/* ####################### Key 2 ######################## */

	fprintf( stderr, "Key 2:\n" );

		// get uint attrib
	result = Tspi_SetAttribUint32( hKey2,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_USAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not a storage key */
		if( ES != TSS_KEYUSAGE_STORAGE )
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
	fprintf( stderr, "\t\tUsage (11=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey2,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_MIGRATABLE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is migratable */
		if( ES == FLAG_MIGRATABLE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tMigratable (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey2,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_REDIRECTED,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is redirected */
		if( ES == FLAG_REDIRECTION )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tRedirected (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey2,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_VOLATILE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not volatile */
		if( ES != FLAG_VOLATILE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tVolatile (non-zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey2,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it requires authorization */
		if( ES != TPM_AUTH_NEVER )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tAuthDataUsage (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey2,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ALGORITHM,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not RSA */
		if( ES != TSS_ALG_RSA )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tAlgorithm (1=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey2,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_ES_RSAESOAEP_SHA1_MGF1 */
		if( ES != TSS_ES_RSAESOAEP_SHA1_MGF1 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tEncscheme (3=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey2,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_SS_NONE (no sig scheme) */
		if( ES != TSS_SS_NONE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tSigscheme (1=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey2,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_KEYFLAGS,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tKeyflags: %x\n", ES );

	result = Tspi_SetAttribUint32( hKey2,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHUSAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tAuthUsage: %x\n", ES );

/* #################### Key 3 ###################### */

	fprintf( stderr, "Key 3:\n" );

		// get uint attrib
	result = Tspi_SetAttribUint32( hKey3,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_USAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not an authchange key */
		if( ES != TSS_KEYUSAGE_AUTHCHANGE )
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
	fprintf( stderr, "\t\tUsage (11=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey3,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_MIGRATABLE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is migratable */
		if( ES == FLAG_MIGRATABLE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tMigratable (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey3,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_REDIRECTED,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is redirected */
		if( ES == FLAG_REDIRECTION )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tRedirected (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey3,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_VOLATILE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not volatile */
		if( ES != FLAG_VOLATILE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tVolatile (non-zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey3,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it does not require authorization */
		if( ES != TPM_AUTH_ALWAYS )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tAuthDataUsage (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey3,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ALGORITHM,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not RSA */
		if( ES != TSS_ALG_RSA )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tAlgorithm (1=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey3,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_ES_RSAESOAEP_SHA1_MGF1 */
		if( ES != TSS_ES_RSAESOAEP_SHA1_MGF1 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tEncscheme (3=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey3,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_SS_NONE (no sig scheme) */
		if( ES != TSS_SS_NONE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tSigscheme (1=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey3,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_KEYFLAGS,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tKeyflags: %x\n", ES );

	result = Tspi_SetAttribUint32( hKey3,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHUSAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tAuthUsage: %x\n", ES );

/* ################### Key 4 #################### */

	fprintf( stderr, "Key 4:\n" );

		// get uint attrib
	result = Tspi_SetAttribUint32( hKey4,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_USAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not a storage key */
		if( ES != TSS_KEYUSAGE_STORAGE )
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
	fprintf( stderr, "\t\tUsage (11=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey4,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_MIGRATABLE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is migratable */
		if( ES == FLAG_MIGRATABLE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tMigratable (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey4,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_REDIRECTED,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is redirected */
		if( ES == FLAG_REDIRECTION )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tRedirected (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey4,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_VOLATILE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not volatile */
		if( ES != FLAG_VOLATILE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tVolatile (non-zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey4,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it requires authorization */
		if( ES != TPM_AUTH_NEVER )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tAuthDataUsage (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey4,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ALGORITHM,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not RSA */
		if( ES != TSS_ALG_RSA )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tAlgorithm (1=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey4,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_ES_RSAESOAEP_SHA1_MGF1 */
		if( ES != TSS_ES_RSAESOAEP_SHA1_MGF1 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tEncscheme (3=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey4,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_SS_NONE (no sig scheme) */
		if( ES != TSS_SS_NONE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tSigscheme (1=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey4,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_KEYFLAGS,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tKeyflags: %x\n", ES );

	result = Tspi_SetAttribUint32( hKey4,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHUSAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tAuthUsage: %x\n", ES );

/* ################### Key 5 #################### */

	fprintf( stderr, "Key 5:\n" );

		// get uint attrib
	result = Tspi_SetAttribUint32( hKey5,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_USAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not an authchange key */
		if( ES != TSS_KEYUSAGE_AUTHCHANGE )
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
	fprintf( stderr, "\t\tUsage (11=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey5,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_MIGRATABLE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is migratable */
		if( ES == FLAG_MIGRATABLE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tMigratable (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey5,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_REDIRECTED,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is redirected */
		if( ES == FLAG_REDIRECTION )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tRedirected (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey5,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_VOLATILE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not volatile */
		if( ES != FLAG_VOLATILE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tVolatile (non-zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey5,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it requires authorization */
		if( ES != TPM_AUTH_ALWAYS )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tAuthDataUsage (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey5,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ALGORITHM,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not RSA */
		if( ES != TSS_ALG_RSA )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tAlgorithm (1=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey5,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_ES_RSAESOAEP_SHA1_MGF1 */
		if( ES != TSS_ES_RSAESOAEP_SHA1_MGF1 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tEncscheme (3=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey5,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_SS_NONE (no sig scheme) */
		if( ES != TSS_SS_NONE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tSigscheme (1=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey5,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_KEYFLAGS,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tKeyflags: %x\n", ES );

	result = Tspi_SetAttribUint32( hKey5,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHUSAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tAuthUsage: %x\n", ES );

/* ###################### Key 6 ##################### */

	fprintf( stderr, "Key 6:\n" );

		// get uint attrib
	result = Tspi_SetAttribUint32( hKey6,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_USAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not a storage key */
		if( ES != TSS_KEYUSAGE_STORAGE )
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
	fprintf( stderr, "\t\tUsage (11=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey6,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_MIGRATABLE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is migratable */
		if( ES == FLAG_MIGRATABLE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tMigratable (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey6,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_REDIRECTED,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is redirected */
		if( ES == FLAG_REDIRECTION )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tRedirected (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey6,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_VOLATILE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is volatile */
		if( ES == FLAG_VOLATILE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tVolatile (non-zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey6,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it requires authorization */
		if( ES != TPM_AUTH_NEVER )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tAuthDataUsage (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey6,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ALGORITHM,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not RSA */
		if( ES != TSS_ALG_RSA )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tAlgorithm (1=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey6,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_ES_RSAESOAEP_SHA1_MGF1 */
		if( ES != TSS_ES_RSAESOAEP_SHA1_MGF1 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tEncscheme (3=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey6,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_SS_NONE (no sig scheme) */
		if( ES != TSS_SS_NONE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tSigscheme (1=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey6,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_KEYFLAGS,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tKeyflags: %x\n", ES );

	result = Tspi_SetAttribUint32( hKey6,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHUSAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tAuthUsage: %x\n", ES );

/* ####################### Key 7 ####################### */

	fprintf( stderr, "Key 7:\n" );

		// get uint attrib
	result = Tspi_SetAttribUint32( hKey7,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_USAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not an authchange key */
		if( ES != TSS_KEYUSAGE_AUTHCHANGE )
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
	fprintf( stderr, "\t\tUsage (11=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey7,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_MIGRATABLE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is migratable */
		if( ES == FLAG_MIGRATABLE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tMigratable (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey7,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_REDIRECTED,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is redirected */
		if( ES == FLAG_REDIRECTION )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tRedirected (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey7,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_VOLATILE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is volatile */
		if( ES == FLAG_VOLATILE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tVolatile (non-zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey7,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it requires authorization */
		if( ES != TPM_AUTH_NEVER )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tAuthDataUsage (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey7,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ALGORITHM,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not RSA */
		if( ES != TSS_ALG_RSA )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tAlgorithm (1=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey7,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_ES_RSAESOAEP_SHA1_MGF1 */
		if( ES != TSS_ES_RSAESOAEP_SHA1_MGF1 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tEncscheme (3=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey7,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_SS_NONE (no sig scheme) */
		if( ES != TSS_SS_NONE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tSigscheme (1=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey7,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_KEYFLAGS,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tKeyflags: %x\n", ES );

	result = Tspi_SetAttribUint32( hKey7,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHUSAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tAuthUsage: %x\n", ES );

/* ####################### Key 8 ####################### */

	fprintf( stderr, "Key 8:\n" );

		// get uint attrib
	result = Tspi_SetAttribUint32( hKey8,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_USAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not a storage key */
		if( ES != TSS_KEYUSAGE_STORAGE )
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
	fprintf( stderr, "\t\tUsage (11=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey8,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_MIGRATABLE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not migratable */
		if( ES != FLAG_MIGRATABLE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tMigratable (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey8,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_REDIRECTED,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is redirected */
		if( ES == FLAG_REDIRECTION )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tRedirected (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey8,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_VOLATILE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is volatile */
		if( ES == FLAG_VOLATILE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tVolatile (non-zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey8,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it requires authorization */
		if( ES != TPM_AUTH_NEVER )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tAuthDataUsage (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey8,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ALGORITHM,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not RSA */
		if( ES != TSS_ALG_RSA )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tAlgorithm (1=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey8,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_ES_RSAESOAEP_SHA1_MGF1 */
		if( ES != TSS_ES_RSAESOAEP_SHA1_MGF1 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tEncscheme (3=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey8,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_SS_NONE (no sig scheme) */
		if( ES != TSS_SS_NONE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tSigscheme (1=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey8,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_KEYFLAGS,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tKeyflags: %x\n", ES );

	result = Tspi_SetAttribUint32( hKey8,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHUSAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tAuthUsage: %x\n", ES );

/* ################### Key 9 ################### */

	fprintf( stderr, "Key 9:\n" );

		// get uint attrib
	result = Tspi_SetAttribUint32( hKey9,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_USAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not a storage key */
		if( ES != TSS_KEYUSAGE_SIGN )
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
	fprintf( stderr, "\t\tUsage (11=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey9,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_MIGRATABLE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not migratable */
		if( ES != FLAG_MIGRATABLE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tMigratable (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey9,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_REDIRECTED,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is redirected */
		if( ES == FLAG_REDIRECTION )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tRedirected (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey9,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_VOLATILE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not volatile */
		if( ES != FLAG_VOLATILE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tVolatile (non-zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey9,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it does not require authorization */
		if( ES != TPM_AUTH_ALWAYS )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tAuthDataUsage (zero=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey9,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ALGORITHM,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not RSA */
		if( ES != TSS_ALG_RSA )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tAlgorithm (1=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey9,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_ES_NONE */
		if( ES != TSS_ES_NONE )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tEncscheme (3=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey9,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not TSS_SS_RSASSAPKCS1V15_SHA1 */
		if( ES != TSS_SS_RSASSAPKCS1V15_SHA1 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tSigscheme (1=Pass): %x\n", ES );

	result = Tspi_SetAttribUint32( hKey9,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_KEYFLAGS,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tKeyflags: %x\n", ES );

	result = Tspi_SetAttribUint32( hKey9,
					TSS_TSPATTRIB_KEY_INFO,
					TSS_TSPATTRIB_KEYINFO_AUTHUSAGE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		print_success( function1, result);
		exitCode = 0;
	}
	fprintf( stderr, "\t\tAuthUsage: %x\n", ES );
#endif

	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( exitCode );
}
