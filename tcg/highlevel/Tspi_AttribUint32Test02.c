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
 *	Tspi_AttribUint32Test02.c
 *
 * DESCRIPTION
 *	This test will use Tspi_GetAttribUint32 to show that
 *		each key has the proper attributes (individual
 *		flags). This test checks for proper rsakey
 *		settings: size and number of primes. 
 *		Expected values are based on the initFlags
 *		used when the keys were created in hlsetup.
 *		
 *	hlsetup must be run prior to this test.
 *	
 *	Added defaultKeySize. Using defaultKeySize=2048 for now. 
 * 	    	According to the TSS Specification V1.10, 
 *		Tspi_Context_GetCapability has a TBD attribute
 *		which will return the default key length.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Load 10 Keys
 *
 *	Test:
 *		Call Tspi_GetAttribUint32 then if it succeeds
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
 *	Modified by Debora Velarde, dvelarde@us.ibm.com, 09/04.
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
	char			*function = "Tspi_AttribUint32Test02";
	char			*function1 = "Tspi_GetAttribUint32";
	TSS_HKEY		hParentKey;
	TSS_RESULT		result;
	UINT32			ES;
	int			exitCode, value01, value02, tempFlag, i;
	int			defaultKeySize;

	defaultKeySize=2048;

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

		// get uint attrib
	result = Tspi_GetAttribUint32( hKey0,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if key size not 2048 */
		if( ES != 2048 )
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
	fprintf( stderr, "\t\tKey Size: %x\n", ES);

	result = Tspi_GetAttribUint32( hKey0,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_PRIMES,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* RSA keys have 2 prime factors */
		if( ES != 2 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tPrimes: %x\n", ES );

/* ################# Key 1 ##################### */

	fprintf( stderr, "Key 1:\n" );

		// get uint attrib
	result = Tspi_GetAttribUint32( hKey1,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* Assumption is, if you create a key with initFlags=0, should use defaults */
		/* if it is not equal to the default key size */
		if( ES != defaultKeySize )
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
	fprintf( stderr, "\t\tKey Size: %x\n", ES );

	result = Tspi_GetAttribUint32( hKey1,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_PRIMES,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* RSA keys have 2 prime factors */
		if( ES != 2 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tPrimes: %x\n", ES );

/* ####################### Key 2 ######################## */

	fprintf( stderr, "Key 2:\n" );

		// get uint attrib
	result = Tspi_GetAttribUint32( hKey2,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if it is not equal to the default key size */
		if( ES != defaultKeySize )
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
	fprintf( stderr, "\t\tKey Size: %x\n", ES );

	result = Tspi_GetAttribUint32( hKey2,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_PRIMES,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* RSA keys have 2 prime factors */
		if( ES != 2 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tPrimes: %x\n", ES );

/* #################### Key 3 ###################### */

	fprintf( stderr, "Key 3:\n" );

		// get uint attrib
	result = Tspi_GetAttribUint32( hKey3,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if key size is not equal to default */
		if( ES != defaultKeySize )
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
	fprintf( stderr, "\t\tKey Size: %x\n", ES );

	result = Tspi_GetAttribUint32( hKey3,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_PRIMES,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* RSA keys have 2 prime factors */
		if( ES != 2 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tPrimes: %x\n", ES );

/* ################### Key 4 #################### */

	fprintf( stderr, "Key 4:\n" );

		// get uint attrib
	result = Tspi_GetAttribUint32( hKey4,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if key size is not 8192 */
		if( ES != 8192 )
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
	fprintf( stderr, "\t\tKey Size: %x\n", ES );

	result = Tspi_GetAttribUint32( hKey4,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_PRIMES,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* RSA keys have 2 prime factors */
		if( ES != 2 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tPrimes: %x\n", ES );

/* ################### Key 5 #################### */

	fprintf( stderr, "Key 5:\n" );

		// get uint attrib
	result = Tspi_GetAttribUint32( hKey5,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if key size is not 4096 */
		if( ES != 4096 )
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
	fprintf( stderr, "\t\tKey Size: %x\n", ES );

	result = Tspi_GetAttribUint32( hKey5,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_PRIMES,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* RSA keys have 2 prime factors */
		if( ES != 2 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tPrimes: %x\n", ES );

/* ###################### Key 6 ##################### */

	fprintf( stderr, "Key 6:\n" );

		// get uint attrib
	result = Tspi_GetAttribUint32( hKey6,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if key size is not equal to default */
		if( ES != defaultKeySize )
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
	fprintf( stderr, "\t\tKey Size: %x\n", ES );

	result = Tspi_GetAttribUint32( hKey6,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_PRIMES,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* RSA keys have 2 prime factors */
		if( ES != 2 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tPrimes: %x\n", ES );

/* ####################### Key 7 ####################### */

	fprintf( stderr, "Key 7:\n" );

		// get uint attrib
	result = Tspi_GetAttribUint32( hKey7,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if key size is not 8192 */
		if( ES != 8192 )
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
	fprintf( stderr, "\t\tKey Size: %x\n", ES );

	result = Tspi_GetAttribUint32( hKey7,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_PRIMES,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* RSA keys have 2 prime factors */
		if( ES != 2 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tPrimes: %x\n", ES );

/* ####################### Key 8 ####################### */

	fprintf( stderr, "Key 8:\n" );

		// get uint attrib
	result = Tspi_GetAttribUint32( hKey8,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if key size is not 4096 */
		if( ES != 4096 )
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
	fprintf( stderr, "\t\tKey Size: %x\n", ES );

	result = Tspi_GetAttribUint32( hKey8,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_PRIMES,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* RSA keys have 2 prime factors */
		if( ES != 2 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tPrimes: %x\n", ES );

/* ################### Key 9 ################### */

	fprintf( stderr, "Key 9:\n" );

		// get uint attrib
	result = Tspi_GetAttribUint32( hKey9,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* if key size is not 2048 */
		if( ES != 2048 )
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
	fprintf( stderr, "\t\tKey Size: %x\n", ES );

	result = Tspi_GetAttribUint32( hKey9,
					TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_PRIMES,
					&ES );
	if ( result != TSS_SUCCESS )
	{
		print_error( function1, result );
		exitCode = 1;
	}
	else
	{
		/* RSA keys have 2 prime factors */
		if( ES != 2 )
		{
			print_error( function1, result );
			exitCode = 1;
		}
		else
		{
			print_success( function1, result);
		}
	}
	fprintf( stderr, "\t\tPrimes: %x\n", ES );

	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( exitCode );
}
