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
 *	key_conflict01.c
 *
 * DESCRIPTION
 *
 *	SRK
 *	 \
 *	  hKey0 (no auth)
 *	   \
 *	    hKey1 (auth)
 *	     \
 *	      hKey2 (no auth)
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
 *      0       TSS_KEY_TYPE_STORAGE | TSS_KEY_NO_AUTHORIZATION
 *      1       TSS_KEY_TYPE_STORAGE | TSS_KEY_AUTHORIZATION
 *      2       TSS_KEY_TYPE_STORAGE | TSS_KEY_NO_AUTHORIZATION
 *
 *	Test:
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
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <trousers/tss.h>

#include "../common/common.h"

#define KEY_CONFLICT_NUM_THREADS	4


void *thread_v1_1(void *);

int
main( int argc, char **argv )
{
	char		*version;

	version = parseArgs( argc, argv );
		// if it is not version 1.1, print error
	if( strcmp(version, "1.1") )
		print_wrongVersion();
	else
		return main_v1_1();
}

int
main_v1_1(void)
{
	char *function = "key_conflict master thread";
	pthread_t thread_ids[KEY_CONFLICT_NUM_THREADS];
	int result, i, j;
	void *ret_val;
	UINT32 test_result = 0;

	srand(time(0));

	/* start up the threads */
	for (i = 0; i < KEY_CONFLICT_NUM_THREADS; i++) {
		if ((result = pthread_create(&thread_ids[i], NULL, thread_v1_1, (void *)i))) {
			printf( "pthread_create (thread %d) returned %d\n", i, result );
			for (j = 0; j < i; j++)
				pthread_join(thread_ids[j], &ret_val);
			exit(result);
		}
	}

	/* wait for all threads to finish */
	for (i = 0; i < KEY_CONFLICT_NUM_THREADS; i++) {
		UINT32 ret;

		pthread_join(thread_ids[i], &ret_val);

		ret = *((UINT32 *)ret_val);
		if (ret) {
			/* set the overall test result to failure */
			test_result = ret;
		}
	}

	if (test_result)
		goto done;

	print_success(function, 0);
	print_end_test(function);
	return( 0 );

done:
	print_error_exit(function, err_string(test_result));
	exit(test_result);
}

void *
thread_v1_1(void *num)
{
	char		function[80] = "key_conflict ";
	TSS_HCONTEXT    hContext;
	TSS_HKEY        hSRK;
	TSS_HKEY	hKey0, hKey1, hKey2;
	TSS_RESULT	result;
	TSS_HENCDATA	hEncData;
	TSS_HPOLICY	srkUsagePolicy, keyUsagePolicy;
	int thread_num = (int)num;
	char name[10];
	BYTE rgbDataToBind[] = {62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62};
	UINT32 ulDataLength = 16;

	UINT32 pulDataLength;
	BYTE *prgbDataToUnBind;


	sprintf(name, "THREAD%d", thread_num);
	strcat(function, name);

	print_begin_test( function );

		// Create Context
	result = Tspi_Context_Create( &hContext );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Create", result );
		print_error_exit( function, err_string(result) );
		pthread_exit( (void *)&result );
	}

		// Connect to Context
	result = Tspi_Context_Connect( hContext, NULL );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Connect", result );
		goto done;
	}

	fprintf(stderr, "%s connected with context 0x%x\n", function, hContext);

		//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						SRK_UUID, &hSRK );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hSRK)", result );
		goto done;
	}

		//Get Policy Object
	result = Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE,
					&srkUsagePolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		goto done;
	}

		//Set Secret
	result = Tspi_Policy_SetSecret( srkUsagePolicy, TSS_SECRET_MODE_PLAIN,
				0, NULL );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		goto done;
	}

	/* ######## Start Key 0 ######## */
	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
						TSS_KEY_SIZE_2048 |
						TSS_KEY_TYPE_STORAGE |
						TSS_KEY_NO_AUTHORIZATION,
						&hKey0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (key 0)", result );
		goto done;
	}

	result = Tspi_Key_CreateKey( hKey0, hSRK, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (key 0)", result );
		goto done;
	}

	fprintf( stderr, "\t\tKey 0 Finished (handle: 0x%x)\n", hKey0 );
	/* ######## End Key 0 ######## */
	/* ######## Start Key 1 ######## */
	result = Tspi_Context_CreateObject( hContext,
						TSS_OBJECT_TYPE_RSAKEY,
						TSS_KEY_TYPE_STORAGE |
						TSS_KEY_AUTHORIZATION,
						&hKey1 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (key 1)", result );
		goto done;
	}

	result = Tspi_GetPolicyObject( hKey1, TSS_POLICY_USAGE,
					&keyUsagePolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		goto done;
	}

		//Set Secret
	result = Tspi_Policy_SetSecret( keyUsagePolicy, TSS_SECRET_MODE_PLAIN,
				sizeof(KEY_PWD), KEY_PWD );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		goto done;
	}

	result = Tspi_Key_LoadKey( hKey0, hSRK );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_LoadKey (hKey0)", result );
		goto done;
	}

	result = Tspi_Key_CreateKey( hKey1, hKey0, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (key 1)", result );
		goto done;
	}

	fprintf( stderr, "\t\tKey 1 Finished (handle: 0x%x)\n", hKey1 );
	/* ######## End Key 1 ######## */

	/* ######## Start Key 2 ######## */
	result = Tspi_Context_CreateObject( hContext, TSS_OBJECT_TYPE_RSAKEY,
						TSS_KEY_TYPE_BIND |
						TSS_KEY_NO_AUTHORIZATION,
						&hKey2 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (key 2)", result );
		goto done;
	}

	result = Tspi_Key_LoadKey( hKey1, hKey0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_LoadKey (hKey1)", result );
		goto done;
	}

	result = Tspi_Key_CreateKey( hKey2, hKey1, 0 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_CreateKey (key 2)", result );
		goto done;
	}

	result = Tspi_Key_LoadKey( hKey2, hKey1 );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Key_LoadKey (hKey1)", result );
		goto done;
	}

	fprintf( stderr, "\t\tKey 2 Finished (handle: 0x%x)\n", hKey2 );

	fprintf( stderr, "\t\tBinding, then Unbinding some data.\n" );

	result = Tspi_Context_CreateObject( hContext,
						TSS_OBJECT_TYPE_ENCDATA,
						TSS_ENCDATA_BIND, &hEncData );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_CreateObject (hEncData)", result );
		goto done;
	}

		// Data Bind
	result = Tspi_Data_Bind( hEncData, hKey2, ulDataLength, rgbDataToBind );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Data_Bind", result );
		goto done;
	}


	result = Tspi_Data_Unbind( hEncData, hKey2, &pulDataLength, &prgbDataToUnBind );
	if ( result != TSS_SUCCESS )
	{
		if( !(checkNonAPI(result)) )
		{
			print_error( function, result );
			goto done;
		}
		else
		{
			print_error_nonapi( function, result );
			goto done;
		}
	}
	else
	{
		if ((pulDataLength == ulDataLength) &&
			!memcmp(prgbDataToUnBind, rgbDataToBind, pulDataLength))
			print_success( function, result );
		else
			printf("%s: unbound Data doesn't match original data.\n", function);
	}


	/* ######## End Key 2 ######## */

	print_success( function, result );
	print_end_test( function );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	pthread_exit((void *)&result);

done:
	print_error_exit( function, err_string(result) );
	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
	pthread_exit((void *)&result);
}
