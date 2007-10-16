/*
 *
 *   Copyright (C) International Business Machines  Corp., 2007
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


#include <stdio.h>
#include "common.h"


int
main( int argc, char **argv )
{
	char *			function = "InvalidateAllFamilies";
	TSS_HCONTEXT		hContext;
	TSS_HKEY		hSRK;
	TSS_HTPM		hTPM;
	TSS_HPOLICY		hTPMPolicy;
	UINT32			famTableSize, delTableSize;
	TSS_FAMILY_TABLE_ENTRY	famEntry, *famTable;
	TSS_DELEGATION_TABLE_ENTRY *delTable;
	TSS_HDELFAMILY		hFamily;
	UINT32			i;
	UINT64			offset;
	TSS_RESULT		result;

	print_begin_test( function );

	result = connect_load_all(&hContext, &hSRK, &hTPM);
	if ( result != TSS_SUCCESS )
	{
		print_error( "connect_load_all", result );
		goto done;
	}

	result = Tspi_GetPolicyObject( hTPM, TSS_POLICY_USAGE, &hTPMPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		goto done;
	}

	result = Tspi_Policy_SetSecret( hTPMPolicy, TESTSUITE_OWNER_SECRET_MODE,
					TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		goto done;
	}

	result = Tspi_TPM_Delegate_ReadTables(hContext, &famTableSize, &famTable, &delTableSize, &delTable);
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_TPM_Delegate_ReadTables", result );
		goto done;
	}

	for (i = 0, offset = 0; i < famTableSize; i++) {
		Trspi_UnloadBlob_TSS_FAMILY_TABLE_ENTRY(&offset, famTable, &famEntry);

		printf("Attempting to invalidate family ID %u\n", famEntry.familyID);
		result = Tspi_TPM_Delegate_GetFamily(hTPM, famEntry.familyID, &hFamily);
		if ( result != TSS_SUCCESS )
		{
			print_error( function, result );
			goto done;
		}

		result = Tspi_TPM_Delegate_InvalidateFamily(hTPM, hFamily);
		if ( result != TSS_SUCCESS )
		{
			print_error( function, result );
			goto done;
		}
	}

	print_success( function, result );
	print_end_test( function );

done:
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( 0 );
}
