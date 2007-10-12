/*
 *
 *   Copyright (C) International Business Machines  Corp., 2004, 2005, 2007
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
 *	policy_check_lifetime04.c
 *
 * DESCRIPTION
 *	This test will verify if the TSS behaves properly when the policy
 *  is set to be used for some seconds, then used once and set again to be used always.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Get TPM Object
 *		Get TPM's Policy Object
 * 		Set Lifetime to the TPM's policy object to TIMER seconds
 *		Set Secret
 *
 *	Test:
 * 		Ensure the Policy usage is not set as ALWAYS
 *		Call TPM_GetStatus then if it does not succeed
 *		Make sure that it returns the proper return codes
 *      Sleep for TIMER -3 seconds
 *		Set policy's usage as ALWAYS 
 *      Call some TPM_GetStatus again, verify if it doesn't generate auth erros.
 * 		Check if policy's usage is set as ALWAYS 
 *
 *	Cleanup:
 *		Free memory relating to hContext
 *		Close context
 *
 * USAGE
 *      First parameter is --options
 *                         -v or --version
 *      Second parameter is the version of the test case to be run
 *      This test case is currently only implemented for v1.2
 *
 * HISTORY
 *      Ramon Gomes Brandão, ramongb@br.ibm.com, 09/07
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include <unistd.h>
#include "common.h"

#define TIMER 5

int
main( int argc, char **argv )
{
	char version;

	version = parseArgs( argc, argv );
	if (version == TESTSUITE_TEST_TSS_1_2 ||
	    version == TESTSUITE_TEST_TSS_1_1)
		main_v1_2(version);
	else
		print_wrongVersion();
}

int
main_v1_2( char version )
{
	char			*function = "policy_check_lifetime04";
	TSS_HCONTEXT	hContext;
	TSS_HTPM		hTPM;
	TSS_HPOLICY		hPolicy;
	TSS_BOOL		state;
	TSS_RESULT		result;
	UINT32			remainingTimer;

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

		// Retrieve TPM object of context
	result = Tspi_Context_GetTpmObject( hContext, &hTPM );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_GetTpmObject", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	result = Tspi_GetPolicyObject( hTPM, TSS_POLICY_USAGE, &hPolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	
	//Sets the policy Lifetime Timer
	result = Tspi_SetAttribUint32( hPolicy, TSS_TSPATTRIB_POLICY_SECRET_LIFETIME,
			TSS_TSPATTRIB_POLSECRET_LIFETIME_TIMER, TIMER );
	if (result != TSS_SUCCESS){
		print_error("Tspi_SetAttribUint32", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Sets the secret and fires the timer
	result = Tspi_Policy_SetSecret( hPolicy, TESTSUITE_OWNER_SECRET_MODE,
					TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	
		//Ensure Secret usages is not always
	result = Tspi_GetAttribUint32(hPolicy, TSS_TSPATTRIB_POLICY_SECRET_LIFETIME,
			TSS_TSPATTRIB_POLSECRET_LIFETIME_ALWAYS, &remainingTimer);
	if ( result != TSS_SUCCESS || (remainingTimer) ){
		if ( remainingTimer ){
			fprintf( stderr, "\tError: Policy Usage is set as always: (%u)\n",
					remainingTimer );
			print_error( function, result );
		}else{
			print_error( "Tspi_Policy_SetSecret", result );
		}
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		//Get status - first call within TIMER seconds
	result = Tspi_TPM_GetStatus( hTPM, TSS_TPMSTATUS_SETOWNERINSTALL,
					&state );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_TPM_GetStatus(1)", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	
		//Sleeps for TIMER - 3 seconds
	fprintf( stdout, "Sleeping for %u seconds\n", TIMER-3);
	sleep( TIMER - 3 );
	
		//Ensures the usage timer has decremented
	result = Tspi_GetAttribUint32(hPolicy, TSS_TSPATTRIB_POLICY_SECRET_LIFETIME,
			TSS_TSPATTRIB_POLSECRET_LIFETIME_TIMER, &remainingTimer);
	if ( result != TSS_SUCCESS || (remainingTimer <= TIMER-3)){
		if ( remainingTimer <= TIMER-3 ){
			fprintf( stderr, "\tError: Invalid policy timer after usage: (%u)\n",
					remainingTimer );
			print_error( function, result );
		}else{
			print_error( "Tspi_GetAttribUint32", result );
		}
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	
		//Sets the policy Lifetime as always
	result = Tspi_SetAttribUint32(hPolicy, TSS_TSPATTRIB_POLICY_SECRET_LIFETIME,
			TSS_TSPATTRIB_POLSECRET_LIFETIME_ALWAYS, 0);
	if (result != TSS_SUCCESS){
		print_error("Tspi_SetAttribUint32", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
	
		//Ensure Secret usages is always
	result = Tspi_GetAttribUint32(hPolicy, TSS_TSPATTRIB_POLICY_SECRET_LIFETIME,
			TSS_TSPATTRIB_POLSECRET_LIFETIME_ALWAYS, &remainingTimer);
	if ( result != TSS_SUCCESS || (!remainingTimer) ){
		if ( !remainingTimer ){
			fprintf( stderr, "\tError: Policy Usage is not set as always: (%u)\n",
					remainingTimer );
			print_error( function, result );
		}else{
			print_error( "Tspi_GetAttribUint32", result );
		}
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
		
	//Get status - second call
	result = Tspi_TPM_GetStatus( hTPM, TSS_TPMSTATUS_OWNERSETDISABLE,
			&state );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_TPM_GetStatus(2)", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	
		//Get status - third call
	result = Tspi_TPM_GetStatus( hTPM, TSS_TPMSTATUS_OWNERSETDISABLE,
			&state );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_TPM_GetStatus(3)", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	
		//Get status - fourth call
	result = Tspi_TPM_GetStatus( hTPM, TSS_TPMSTATUS_SETOWNERINSTALL,
			&state );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_TPM_GetStatus(4)", result );
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	
	//Ensure Secret usages is always
	result = Tspi_GetAttribUint32(hPolicy, TSS_TSPATTRIB_POLICY_SECRET_LIFETIME,
			TSS_TSPATTRIB_POLSECRET_LIFETIME_ALWAYS, &remainingTimer);
	if ( result != TSS_SUCCESS || (!remainingTimer) ){
		if ( !remainingTimer ){
			fprintf( stderr, "\tError: Policy Usage is not set as always: (%u)\n",
					remainingTimer );
			print_error( function, result );
		}else{
			print_error( "Tspi_GetAttribUint32", result );
		}
		Tspi_Context_FreeMemory( hContext, NULL );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	
	print_success( function, result);
	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	exit( result );
}
