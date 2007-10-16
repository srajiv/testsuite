/*
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
 *	Tspi_GetAttribData20.c
 *
 * DESCRIPTION
 *	This test will verify that Tspi_GetAttribData and Tspi_GetAttribUint32
 *			returns TSS_SUCCESS using flag TSS_TSPATTRIB_ENCDATA_PCR_LONG.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Create Key Object
 *		Create Enc Data
 *		Load Key By UUID
 *		Create PCR Composite
 *		Set PCR Value
 *
 *	Test:
 *		Call Tspi_GetAttribData then if it does not succeed return error
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
 *      Giampaolo Libralao, glibrala@br.ibm.com - 09/2007.
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include "common.h"


int
main( int argc, char **argv )
{
	char		version;

	version = parseArgs( argc, argv );
	if (version)
		main_v1_1();
	else
		print_wrongVersion();
}

int
main_v1_1( void )
{
	char		*function = "Tspi_GetAttribData20";
	TSS_HCONTEXT	hContext;
	TSS_HKEY	hSRK;
	TSS_HPOLICY	hSrkPolicy;
	BYTE		*rgbDataToSeal = "This is a test";
	BYTE		rgbPcrValue[20];
	TSS_HENCDATA	hEncData;
	TSS_HPCRS	hPcrComposite;
	UINT32		AttribDataSize, pulAttrib;
	BYTE*		AttribData;
	UINT32		ulDataLength = strlen(rgbDataToSeal);
	TSS_RESULT	result,resultFree;
	TSS_FLAG	initFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048  |
				TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
				TSS_KEY_NOT_MIGRATABLE;

	print_begin_test( function );

	memset(rgbPcrValue, 0x5a, sizeof(rgbPcrValue));

		// Create Context
	result = Tspi_Context_Create( &hContext );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Create", result );
		print_end_test(function);
		exit( result );
	}

		// Connect to Context
	result = Tspi_Context_Connect( hContext, get_server(GLOBALSERVER) );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Connect", result );
		print_end_test(function);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Context_CreateObject( hContext,
				TSS_OBJECT_TYPE_ENCDATA,
				TSS_ENCDATA_SEAL, &hEncData );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (hEncData)", result );
		print_end_test(function);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		//Load Key by UUID
	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
				SRK_UUID, &hSRK );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hSRK)", result );
		print_end_test(function);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

#ifndef TESTSUITE_NOAUTH_SRK
	result = Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE, &hSrkPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		print_end_test(function);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_Policy_SetSecret( hSrkPolicy, TESTSUITE_SRK_SECRET_MODE,
				TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		print_end_test(function);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
#endif

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_PCRS,
				TSS_PCRS_STRUCT_INFO_LONG, &hPcrComposite);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (hPcrComposite)",
				result );
		print_end_test(function);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_PcrComposite_SetPcrLocality(hPcrComposite, TPM_LOC_ZERO);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_PcrComposite_SetPcrLocality", result);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_PcrComposite_SetPcrValue( hPcrComposite, 8, 20, rgbPcrValue );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_PcrComposite_SetPcrValue", result );
		print_end_test(function);
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// Data Seal
	result = Tspi_Data_Seal( hEncData, hSRK, ulDataLength, rgbDataToSeal, hPcrComposite );
	if ( result != TSS_SUCCESS )
	{
		if( !(checkNonAPI(result)) )
		{
			print_error( "Tspi_Data_Seal", result );
			print_end_test(function);
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit(result);
		}
		else
		{
			print_error_nonapi( function, result );
			print_end_test(function);
			Tspi_Context_FreeMemory( hContext, NULL );
			Tspi_Context_Close( hContext );
			exit(result);
		}
	}

	// Checking flag and subflags for Tspi_GetAttribData

		//Call GetAttribData for subFlag TSS_TSPATTRIB_ENCDATAPCRLONG_CREATION_SELECTION
	result = Tspi_GetAttribData(hEncData,
			TSS_TSPATTRIB_ENCDATA_PCR_LONG,
			TSS_TSPATTRIB_ENCDATAPCRLONG_CREATION_SELECTION,
			&AttribDataSize, &AttribData);
	if ( result != TSS_SUCCESS ) 
	{
		print_error( "Tspi_GetAttribData - "
						"subflag TSS_TSPATTRIB_ENCDATAPCRLONG_CREATION_SELECTION",
						result );
		print_end_test(function);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	else
	{
		resultFree = Tspi_Context_FreeMemory(hContext, AttribData);
		if ( resultFree != TSS_SUCCESS )
		{
			print_error( "Tspi_Context_FreeMemory", resultFree );
			print_end_test(function);
			exit(resultFree);
		}
		print_success( "Tspi_GetAttribData - "
						"subflag TSS_TSPATTRIB_ENCDATAPCRLONG_CREATION_SELECTION -", result );
	}

		//Call GetAttribData for subFlag TSS_TSPATTRIB_ENCDATAPCRLONG_RELEASE_SELECTION
	result = Tspi_GetAttribData(hEncData,
			TSS_TSPATTRIB_ENCDATA_PCR_LONG,
			TSS_TSPATTRIB_ENCDATAPCRLONG_RELEASE_SELECTION,
			&AttribDataSize, &AttribData);
	if ( result != TSS_SUCCESS ) 
	{
		print_error( "Tspi_GetAttribData - "
						"subflag TSS_TSPATTRIB_ENCDATAPCRLONG_RELEASE_SELECTION",
						result );
		print_end_test(function);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	else
	{
		resultFree = Tspi_Context_FreeMemory(hContext, AttribData);
		if ( resultFree != TSS_SUCCESS )
		{
			print_error( "Tspi_Context_FreeMemory", resultFree );
			print_end_test(function);
			exit(resultFree);
		}
		print_success( "Tspi_GetAttribData - "
						"subflag TSS_TSPATTRIB_ENCDATAPCRLONG_RELEASE_SELECTION -", result );
	}

		//Call GetAttribData for subFlag TSS_TSPATTRIB_ENCDATAPCRLONG_DIGEST_ATCREATION
	result = Tspi_GetAttribData(hEncData,
			TSS_TSPATTRIB_ENCDATA_PCR_LONG,
			TSS_TSPATTRIB_ENCDATAPCRLONG_DIGEST_ATCREATION,
			&AttribDataSize, &AttribData);
	if ( result != TSS_SUCCESS ) 
	{
		print_error( "Tspi_GetAttribData - "
						"subflag TSS_TSPATTRIB_ENCDATAPCRLONG_DIGEST_ATCREATION",
						result );
		print_end_test(function);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	else
	{
		resultFree = Tspi_Context_FreeMemory(hContext, AttribData);
		if ( resultFree != TSS_SUCCESS )
		{
			print_error( "Tspi_Context_FreeMemory", resultFree );
			print_end_test(function);
			exit(resultFree);
		}
		print_success( "Tspi_GetAttribData - "
						"subflag TSS_TSPATTRIB_ENCDATAPCRLONG_DIGEST_ATCREATION -", result );
	}

		//Call GetAttribData for subFlag TSS_TSPATTRIB_ENCDATAPCRLONG_DIGEST_ATRELEASE
	result = Tspi_GetAttribData(hEncData,
			TSS_TSPATTRIB_ENCDATA_PCR_LONG,
			TSS_TSPATTRIB_ENCDATAPCRLONG_DIGEST_ATRELEASE,
			&AttribDataSize, &AttribData);
	if ( result != TSS_SUCCESS ) 
	{
		print_error( "Tspi_GetAttribData - "
						"subflag TSS_TSPATTRIB_ENCDATAPCRLONG_DIGEST_ATRELEASE",
						result );
		print_end_test(function);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	else
	{
		resultFree = Tspi_Context_FreeMemory(hContext, AttribData);
		if ( resultFree != TSS_SUCCESS )
		{
			print_error( "Tspi_Context_FreeMemory", resultFree );
			print_end_test(function);
			exit(resultFree);
		}
		print_success( "Tspi_GetAttribData - "
						"subflag TSS_TSPATTRIB_ENCDATAPCRLONG_DIGEST_ATRELEASE -", result );
	}

	// Checking flag and subflags for Tspi_GetAttribUint32

		//Call Tspi_GetAttribUint32 for subFlag TSS_TSPATTRIB_ENCDATAPCRLONG_LOCALITY_ATCREATION
	result = Tspi_GetAttribUint32(hEncData,
			TSS_TSPATTRIB_ENCDATA_PCR_LONG,
			TSS_TSPATTRIB_ENCDATAPCRLONG_LOCALITY_ATCREATION,
			&pulAttrib);
	if ( result != TSS_SUCCESS ) 
	{
		print_error( "Tspi_GetAttribUint32 - "
						"subflag TSS_TSPATTRIB_ENCDATAPCRLONG_LOCALITY_ATCREATION",
						result );
		print_end_test(function);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	else
	{
		print_success( "Tspi_GetAttribUint32 - "
						"subflag TSS_TSPATTRIB_ENCDATAPCRLONG_LOCALITY_ATCREATION -", result );
	}

		//Call Tspi_GetAttribUint32 for subFlag TSS_TSPATTRIB_ENCDATAPCRLONG_LOCALITY_ATRELEASE
	result = Tspi_GetAttribUint32(hEncData,
			TSS_TSPATTRIB_ENCDATA_PCR_LONG,
			TSS_TSPATTRIB_ENCDATAPCRLONG_LOCALITY_ATRELEASE,
			&pulAttrib);
	if ( result != TSS_SUCCESS ) 
	{
		print_error( "Tspi_GetAttribUint32 - "
						"subflag TSS_TSPATTRIB_ENCDATAPCRLONG_LOCALITY_ATRELEASE",
						result );
		print_end_test(function);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	else
	{
		resultFree = Tspi_Context_FreeMemory(hContext, NULL);
		if ( resultFree != TSS_SUCCESS )
		{
			print_error( "Tspi_Context_FreeMemory", resultFree );
			print_end_test(function);
			exit(resultFree);
		}
		print_success( "Tspi_GetAttribUint32 - "
						"subflag TSS_TSPATTRIB_ENCDATAPCRLONG_LOCALITY_ATRELEASE -", result );
	}

	print_end_test(function);

	Tspi_Context_Close(hContext);
	exit( 0 );
}
