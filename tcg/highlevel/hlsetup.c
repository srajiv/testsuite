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
 *	hlsetup.c
 *
 * DESCRIPTION
 *	This function will provide the basic setup of ten
 *		keys, by creating them in a chain starting
 *		with the first key as a child of the SRK.
 *		Each key will be the child of the key
 *		preceding it.
 *		Each key will then be registered with the
 *		system PS.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		(the following code repeats for the keys)
 *		Create Key Object
 *		Get SRK Handle
 *		Get Policy Object
 *		Set Secret
 *		Create Key Object
 *		Create Key
 *		Register Key
 *		(end of repeating code)
 *
 *      Creates RSA keys with the following attributes:
 *      KEY     initFlags
 *      0       TSS_KEY_SIZE_2048 | TSS_KEY_TYPE_STORAGE
 *      1       0
 *      2       TSS_KEY_DEFAULT
 *      3       TSS_KEY_TYPE_AUTHCHANGE
 *      4       TSS_KEY_SIZE_8192
 *      5       TSS_KEY_SIZE_4096 | TSS_KEY_TYPE_AUTHCHANGE
 *      6       TSS_KEY_NON_VOLATILE
 *      7       TSS_KEY_TYPE_AUTHCHANGE | TSS_KEY_SIZE_8192 | TSS_KEY_NON_VOLATILE
 *      8       TSS_KEY_SIZE_4096 | TSS_KEY_MIGRATABLE | TSS_KEY_NON_VOLATILE
 *      9       TSS_KEY_SIZE_2048 | TSS_KEY_TYPE_SIGNING
 *      10      TSS_KEY_TYPE_LEGACY | TSS_KEY_SIZE_512
 *
 *
 *	Test:
 *		None. This is a common setup function for
 *		higher-level testcases.
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

extern TSS_UUID SRK_UUID;

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
	char		*function = "hlsetup";
	TSS_HCONTEXT    hContext;
	TSS_HKEY        hSRK;
	TSS_HKEY        hMSigningKey;
	TSS_HKEY	hKey;
	TSS_RESULT	result;
	TSS_HPOLICY	srkUsagePolicy;
	int temp;

	print_begin_test( function );

	srand(time(0));

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

		//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						SRK_UUID, &hSRK );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hSRK)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		//Get Policy Object
	result = Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE,
					&srkUsagePolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		//Set Secret
	result = Tspi_Policy_SetSecret( srkUsagePolicy, TSS_SECRET_MODE_PLAIN,
				0, NULL );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* ######## Start Key 0 ######## */
	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
						TSS_KEY_SIZE_2048 |
						TSS_KEY_TYPE_STORAGE,
						&hKey0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (key 0)",
				result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Key_CreateKey( hKey0, hSRK, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (key 0)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_RegisterKey( hContext, hKey0,
						TSS_PS_TYPE_SYSTEM,
						uuid0,
						TSS_PS_TYPE_SYSTEM,
						SRKUUID );
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Context_RegisterKey (uuid0)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	fprintf( stderr, "\t\tKey 0 Finished\n" );
	/* ######## End Key 0 ######## */

	/* ######## Start Key 1 ######## */
	result = Tspi_Context_CreateObject( hContext,
						TSS_OBJECT_TYPE_RSAKEY,
						0,
						&hKey1 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (key 1)",
				result );
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

	result = Tspi_Key_CreateKey( hKey1, hKey0, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (key 1)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_RegisterKey( hContext, hKey1,
						TSS_PS_TYPE_SYSTEM,
						uuid1,
						TSS_PS_TYPE_SYSTEM,
						uuid0 );
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Context_RegisterKey (uuid1)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	fprintf( stderr, "\t\tKey 1 Finished\n" );
	/* ######## End Key 1 ######## */

	/* ######## Start Key 2 ######## */
	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
						TSS_KEY_DEFAULT,
						&hKey2 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (key 2)",
				result );
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

	result = Tspi_Key_CreateKey( hKey2, hKey1, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (key 2)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_RegisterKey( hContext, hKey2,
						TSS_PS_TYPE_SYSTEM,
						uuid2,
						TSS_PS_TYPE_SYSTEM,
						uuid1 );
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Context_RegisterKey (uuid2)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	fprintf( stderr, "\t\tKey 2 Finished\n" );
	/* ######## End Key 2 ######## */

	/* ######## Start Key 3 ######## */
	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
						TSS_KEY_TYPE_AUTHCHANGE,
						//TSS_KEY_AUTHORIZATION,
						&hKey3 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (key 3)",
				result );
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

	result = Tspi_Key_CreateKey( hKey3, hKey2, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (key 3)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_RegisterKey( hContext, hKey3,
						TSS_PS_TYPE_SYSTEM,
						uuid3,
						TSS_PS_TYPE_SYSTEM,
						uuid2 );
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Context_RegisterKey (uuid3)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	fprintf( stderr, "\t\tKey 3 Finished\n" );
	/* ######## End Key 3 ######## */

	/* ######## Start Key 4 ######## */
	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
						TSS_KEY_SIZE_8192,
						&hKey4 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (key 4)",
				result );
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

	result = Tspi_Key_CreateKey( hKey4, hKey3, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (key 4)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_RegisterKey( hContext, hKey4,
						TSS_PS_TYPE_SYSTEM,
						uuid4,
						TSS_PS_TYPE_SYSTEM,
						uuid3 );
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Context_RegisterKey (uuid4)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	fprintf( stderr, "\t\tKey 4 Finished\n" );
	/* ######## End Key 4 ######## */

	/* ######## Start Key 5 ######## */
	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
						TSS_KEY_SIZE_4096 |
						TSS_KEY_TYPE_AUTHCHANGE,
	//					TSS_KEY_NO_AUTHORIZATION,
						&hKey5 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (key 5)",
				result );
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

	result = Tspi_Key_CreateKey( hKey5, hKey4, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (key 5)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_RegisterKey( hContext, hKey5,
						TSS_PS_TYPE_SYSTEM,
						uuid5,
						TSS_PS_TYPE_SYSTEM,
						uuid4 );
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Context_RegisterKey (uuid5)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	fprintf( stderr, "\t\tKey 5 Finished\n" );
	/* ######## End Key 5 ######## */

	/* ######## Start Key 6 ######## */
	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
						//TSS_KEY_AUTHORIZATION |
						//TSS_KEY_MIGRATABLE |
						TSS_KEY_NON_VOLATILE,
						&hKey6 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (key 6)",
				result );
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

	result = Tspi_Key_CreateKey( hKey6, hKey5, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (key 6)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_RegisterKey( hContext, hKey6,
						TSS_PS_TYPE_SYSTEM,
						uuid6,
						TSS_PS_TYPE_SYSTEM,
						uuid5 );
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Context_RegisterKey (uuid6)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	fprintf( stderr, "\t\tKey 6 Finished\n" );
	/* ######## End Key 6 ######## */

	/* ######## Start Key 7 ######## */
	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
						TSS_KEY_TYPE_AUTHCHANGE |
						TSS_KEY_SIZE_8192 |
						//TSS_KEY_NO_AUTHORIZATION |
						//TSS_KEY_MIGRATABLE |
						TSS_KEY_NON_VOLATILE,
						&hKey7 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (key 7)",
				result );
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

	result = Tspi_Key_CreateKey( hKey7, hKey6, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (key 7)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_RegisterKey( hContext, hKey7,
						TSS_PS_TYPE_SYSTEM,
						uuid7,
						TSS_PS_TYPE_SYSTEM,
						uuid6 );
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Context_RegisterKey (uuid7)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	fprintf( stderr, "\t\tKey 7 Finished\n" );
	/* ######## End Key 7 ######## */

	/* ######## Start Key 8 ######## */
	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
						TSS_KEY_SIZE_4096 |
						TSS_KEY_MIGRATABLE |
						TSS_KEY_NON_VOLATILE,
						&hKey8 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (key 8)",
				result );
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

	result = Tspi_Key_CreateKey( hKey8, hKey7, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (key 8)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_RegisterKey( hContext, hKey8,
						TSS_PS_TYPE_SYSTEM,
						uuid8,
						TSS_PS_TYPE_SYSTEM,
						uuid7 );
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Context_RegisterKey (uuid8)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	fprintf( stderr, "\t\tKey 8 Finished\n" );
	/* ######## End Key 8 ######## */

	/* ######## Start Key 9 ######## */
	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
						TSS_KEY_SIZE_2048 |
						TSS_KEY_TYPE_SIGNING |
						TSS_KEY_MIGRATABLE,
						&hKey9 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (key 9)",
				result );
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

	result = Tspi_Key_CreateKey( hKey9, hKey8, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (key 9)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_RegisterKey( hContext, hKey9,
						TSS_PS_TYPE_SYSTEM,
						uuid9,
						TSS_PS_TYPE_SYSTEM,
						uuid8 );
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Context_RegisterKey (uuid9)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	fprintf( stderr, "\t\tKey 9 Finished\n" );
	/* ######## End Key 9 ######## */

	/* ######## Start Key 10 ######## */
/*	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
						TSS_KEY_TYPE_LEGACY |
						TSS_KEY_SIZE_512,
						&hKey10 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (key 10)",
				result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Key_CreateKey( hKey10, hKey8, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (key 10)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_RegisterKey( hContext, hKey10,
						TSS_PS_TYPE_SYSTEM,
						kuuid1,
						TSS_PS_TYPE_SYSTEM,
						uuid8 );
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Context_RegisterKey (kuuid1)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	fprintf( stderr, "\t\tKey 10 Finished\n" );

	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
                                                kuuid1, &hKey10 );
        if ( result != TSS_SUCCESS )
        {
                print_error( "Tspi_Context_LoadKeyByUUID (hKey10)", result );
                print_error_exit( function, err_string(result) );
                Tspi_Context_FreeMemory( hContext, NULL );
                Tspi_Context_Close( hContext );
                exit( result );
        }
*/
	/* ####### End Key 10 ####### */

	print_success( function, result );
	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( 0 );
}
