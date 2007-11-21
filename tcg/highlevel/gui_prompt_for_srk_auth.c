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
 *	gui_prompt_for_srk_auth.c
 *
 * DESCRIPTION
 *	gui_prompt_for_srk_auth will prompt for the srk auth using a popup dialog and use
 *	that policy to do some owner authorized command, passing only on success of the command.
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
 *	Kent Yoder, shpedoikal@gmail.com, 11/07
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
	char			*function = "gui_prompt_for_srk_auth";
	TSS_RESULT		result;
	TSS_HPOLICY		hPolicy;
	TSS_HCONTEXT		hContext;
	TSS_HKEY		hSRK;
	TSS_BOOL		trash;
	UINT32			pubKeySize;
	BYTE			*pubKey;

	print_begin_test( function );

		// Create Context
	result = Tspi_Context_Create( &hContext );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Create", result );
		exit( result );
	}

		// Connect to Context
	result = Tspi_Context_Connect( hContext, NULL );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Connect", result );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID", result );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// get policy
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_POPUP, 0, NULL);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Key_GetPubKey(hSRK, &pubKeySize, &pubKey);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_GetPubKey", result );
	}
	else
	{
		print_success( function, result);
	}

	Tspi_Context_Close( hContext );
	exit( result );
}

