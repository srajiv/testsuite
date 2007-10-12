/*
 *
 *   Copyright (C) International Business Machines  Corp., 2004-2006
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
 *	Tspi_Context_LoadKeyByUUID08.c
 *
 * DESCRIPTION
 *	This test will registera child of the SRK and a grandchild of the SRK
 *	in user PS, then attempt to load the grandchild by UUID.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Load SRK by UUID
 *		Get Policy Object
 *		Set Secret
 *		Create Object
 *		Create Key
 *		Create Object
 *		Create Key
 *
 *	Test:
 *		Call Context_RegisterKey then if it does not succeed
 *		Make sure that it returns the proper return codes
 *		Print results
 *
 *	Cleanup:
 *		Unregister system key
 *		Unregister user key
 *		Free memory related to hContext
 *		Close context
 *
 * USAGE
 *      First parameter is --options
 *                         -v or --version
 *      Second parameter is the version of the test case to be run
 *      This test case is currently only implemented for v1.1 and 1.2
 *
 * HISTORY
 *	Megan Schneider, mschnei@us.ibm.com, 6/04.
 *	Kent Yoder, kyoder@users.sf.net, 09/06
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include <stdlib.h>

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
	char		*function = "Tspi_Context_LoadKeyByUUID08";
	TSS_HKEY	hSRK;
	TSS_UUID	childUUID =	{1,2,3,4,5,{6,7,8,9,10,2}};
	TSS_UUID	parentUUID =		{1,2,3,4,5,{6,7,9,8,10,3}};
	TSS_HKEY	hParentKey, hChildKey;
	TSS_HCONTEXT	hContext;
	TSS_RESULT	result;
	TSS_HPOLICY	srkUsagePolicy;
	UINT32		trash;

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

		// Load SRK
	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						SRK_UUID, &hSRK );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

#ifndef TESTSUITE_NOAUTH_SRK
		// Get SRK Usage Policy
	result = Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE,
					&srkUsagePolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// set secret
	result = Tspi_Policy_SetSecret( srkUsagePolicy, TESTSUITE_SRK_SECRET_MODE,
					TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
#endif

		// create object
	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
						TSS_KEY_SIZE_2048 |
						TSS_KEY_TYPE_STORAGE,
						&hParentKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (signing key)", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// create signing key
	result = Tspi_Key_CreateKey( hParentKey, hSRK, 0 );
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Key_CreateKey", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Key_LoadKey(hParentKey, hSRK);
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Key_LoadKey", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
						TSS_KEY_SIZE_512 |
						TSS_KEY_TYPE_SIGNING,
						&hChildKey );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (signing key)", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// create signing key
	result = Tspi_Key_CreateKey( hChildKey, hParentKey, 0 );
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Key_CreateKey", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Key_UnloadKey(hParentKey);
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Key_UnloadKey", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	/* unregister it to make sure we succeed */
	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_USER,
					childUUID,
					&trash );
	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_USER,
					parentUUID,
					&trash );
		// register key
	result = Tspi_Context_RegisterKey( hContext, hParentKey,
						TSS_PS_TYPE_USER,
						parentUUID,
						TSS_PS_TYPE_SYSTEM,
						SRK_UUID );
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Context_RegisterKey", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_RegisterKey( hContext, hChildKey,
						TSS_PS_TYPE_USER,
						childUUID,
						TSS_PS_TYPE_USER,
						parentUUID );
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Context_RegisterKey", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_CloseObject(hContext, hChildKey);
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Context_CloseObject", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	hChildKey = 0;

	result = Tspi_Context_CloseObject(hContext, hParentKey);
	if ( (result != TSS_SUCCESS) )
	{
		print_error( "Tspi_Context_CloseObject", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	hParentKey = 0;

	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_USER,
					    childUUID, &hChildKey);
	if (result != TSS_SUCCESS)
	{
		if( !(checkNonAPI(result)) )
		{
			print_error( function, result );
		}
		else
		{
			print_error_nonapi( function, result );
		}
	}
	else
	{
		print_success( function, result );
	}

	print_end_test( function );

	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_USER,	childUUID,
					&hChildKey );
	Tspi_Context_UnregisterKey( hContext, TSS_PS_TYPE_USER, parentUUID,
					&hParentKey );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( result );
}
