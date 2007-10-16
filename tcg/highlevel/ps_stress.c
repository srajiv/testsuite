/*
 *
 *   Copyright (C) International Business Machines  Corp., 2006
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
 *     ps_stress.c
 *
 * DESCRIPTION
 *     This test creates 3 keys, one of each size, 512, 1024 and 2048 bits.
 *     It then registers them and closes the TSP context. Then, it
 *     unregisters and re-registers the keys in varying order, using each of
 *     them to sign and verify data while unregistered, in order to check their
 *     integrity.
 *
 * ALGORITHM
 *
 * USAGE
 *      First parameter is --options
 *                         -v or --version
 *      Second parameter is the version of the test case to be run
 *      This test case is currently only implemented for v1.1
 *
 * HISTORY
 *      Written by Kent Yoder <kyoder@users.sf.net>
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdio.h>
#include <string.h>

#include "common.h"

//#define PS_TO_TEST	TSS_PS_TYPE_SYSTEM
#define PS_TO_TEST	TSS_PS_TYPE_USER

#define ERR(x, ...)	fprintf(stderr, "%s:%d " x "\n", __FILE__, __LINE__, ##__VA_ARGS__)

TSS_HKEY        hSRK;
TSS_HCONTEXT	hContext;
char *function = "ps_stress";

TSS_UUID uuids[] = {
	{ 0xf0000000, 0, 0, 0, 0, { 0, 0, 0, 0, 0, 0 } },
	{ 0x0f000000, 0, 0, 0, 0, { 0, 0, 0, 0, 0, 0 } },
	{ 0xf000000f, 0, 0, 0, 0, { 0, 0, 0, 0, 0, 0 } }
};

TSS_RESULT
disconnect_and_reconnect()
{
	TSS_RESULT result;
	TSS_HPOLICY srkUsagePolicy;

	if ((result = Tspi_Context_Close(hContext))) {
		print_error( "Tspi_Context_Close", result );
		return result;
	}

		// Create Context
	result = Tspi_Context_Create( &hContext );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Create", result );
		print_error_exit( function, err_string(result) );
	}

		// Connect to Context
	result = Tspi_Context_Connect( hContext, NULL );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Connect", result );
		return result;
	}

	ERR("%s connected with context 0x%x", function, hContext);

		//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						SRK_UUID, &hSRK );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hSRK)", result );
		return result;
	}

#ifndef TESTSUITE_NOAUTH_SRK
		//Get Policy Object
	result = Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE,
					&srkUsagePolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		return result;
	}

		//Set Secret
	result = Tspi_Policy_SetSecret( srkUsagePolicy, TESTSUITE_SRK_SECRET_MODE,
				TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		return result;
	}
#endif

	return TSS_SUCCESS;
}

TSS_RESULT
unregister_and_test(TSS_UUID uuid, TSS_HKEY *phKey)
{
	TSS_RESULT result;

	/* unregister the middle key */
	if ((result = Tspi_Context_UnregisterKey(hContext, PS_TO_TEST,
						 uuid, phKey))) {
		ERR("Error unregistering key");
		return result;
	}

	if ((result = Tspi_Key_LoadKey(*phKey, hSRK))) {
		ERR("Error loading key");
		return result;
	}

	//return bind_and_unbind(hContext, *phKey);
	return sign_and_verify(hContext, *phKey);
}

int
main( int argc, char **argv )
{
	char		*version;

	//version = parseArgs( argc, argv );
		// if it is not version 1.1, print error
	if( strcmp(argv[2], "1.1") )
		print_wrongVersion();
	else
		return main_v1_1();
}

int
main_v1_1()
{
	int i;
	UINT32 test_result = 0;
	TSS_HKEY key_handles[3];

	TSS_RESULT	result;
	TSS_HPOLICY	srkUsagePolicy;

	print_begin_test( function );

		// Create Context
	result = Tspi_Context_Create( &hContext );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Create", result );
		print_error_exit( function, err_string(result) );
	}

		// Connect to Context
	result = Tspi_Context_Connect( hContext, NULL );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_Connect", result );
		goto done;
	}

	ERR("%s connected with context 0x%x", function, hContext);

		//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID( hContext, TSS_PS_TYPE_SYSTEM,
						SRK_UUID, &hSRK );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Context_LoadKeyByUUID (hSRK)", result );
		goto done;
	}

#ifndef TESTSUITE_NOAUTH_SRK
		//Get Policy Object
	result = Tspi_GetPolicyObject( hSRK, TSS_POLICY_USAGE,
					&srkUsagePolicy );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetPolicyObject", result );
		goto done;
	}

		//Set Secret
	result = Tspi_Policy_SetSecret( srkUsagePolicy, TESTSUITE_SRK_SECRET_MODE,
				TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_Policy_SetSecret", result );
		goto done;
	}
#endif

	/* create one key of each size, 512, 1024 and 2048 */
	if ((result = create_key(hContext,
				 TSS_KEY_SIZE_512|TSS_KEY_TYPE_LEGACY|TSS_KEY_NO_AUTHORIZATION,
				 hSRK, &key_handles[0]))) {
		ERR("Error creating key 512");
		goto done;
	}
	if ((result = create_key(hContext,
				 TSS_KEY_SIZE_1024|TSS_KEY_TYPE_LEGACY|TSS_KEY_NO_AUTHORIZATION,
				 hSRK, &key_handles[1]))) {
		ERR("Error creating key 1024");
		goto done;
	}
	if ((result = create_key(hContext,
				 TSS_KEY_SIZE_2048|TSS_KEY_TYPE_LEGACY|TSS_KEY_NO_AUTHORIZATION,
				 hSRK, &key_handles[2]))) {
		ERR("Error creating key 2048");
		goto done;
	}

	/*
	 * uuid[0] = 512bit key
	 * uuid[1] = 1024bit key
	 * uuid[2] = 2048bit key
	 */

	/* Register them from smallest to largest */
	if ((result = Tspi_Context_RegisterKey(hContext, key_handles[0],
					       PS_TO_TEST, uuids[0],
					       TSS_PS_TYPE_SYSTEM, SRK_UUID))) {
		ERR("Error registering key 0");
		goto done;
	}
	if ((result = Tspi_Context_RegisterKey(hContext, key_handles[1],
					       PS_TO_TEST, uuids[1],
					       TSS_PS_TYPE_SYSTEM, SRK_UUID))) {
		ERR("Error registering key 1");
		goto done;
	}
	if ((result = Tspi_Context_RegisterKey(hContext, key_handles[2],
					       PS_TO_TEST, uuids[2],
					       TSS_PS_TYPE_SYSTEM, SRK_UUID))) {
		ERR("Error registering key 2");
		goto done;
	}

	if ((result = disconnect_and_reconnect())) {
		ERR("Error reconnecting");
		goto done;
	}

	/* unregister the middle key */
	if ((result = unregister_and_test(uuids[1], &key_handles[1]))) {
		ERR("Error testing key 1024 [512][1024][2048]");
		goto done;
	}

	/* re-register the middle key at the end */
	if ((result = Tspi_Context_RegisterKey(hContext, key_handles[1],
					       PS_TO_TEST, uuids[1],
					       TSS_PS_TYPE_SYSTEM, SRK_UUID))) {
		ERR("Error registering key 1024 [512][2048][1024]");
		goto done;
	}

	if ((result = disconnect_and_reconnect())) {
		ERR("Error reconnecting");
		goto done;
	}

	/* unregister the middle key again */
	if ((result = unregister_and_test(uuids[2], &key_handles[2]))) {
		ERR("Error testing key 2048 [512][2048][1024]");
		goto done;
	}

	/* re-register the middle key at the end */
	if ((result = Tspi_Context_RegisterKey(hContext, key_handles[2],
					       PS_TO_TEST, uuids[2],
					       TSS_PS_TYPE_SYSTEM, SRK_UUID))) {
		ERR("Error registering key 2048 [512][1024][2048]");
		goto done;
	}

	if ((result = disconnect_and_reconnect())) {
		ERR("Error reconnecting");
		goto done;
	}

	/* unregister the first key */
	if ((result = unregister_and_test(uuids[0], &key_handles[0]))) {
		ERR("Error testing key 512 [512][1024][2048]");
		goto done;
	}

	/* re-register it back at the end */
	if ((result = Tspi_Context_RegisterKey(hContext, key_handles[0],
					       PS_TO_TEST, uuids[0],
					       TSS_PS_TYPE_SYSTEM, SRK_UUID))) {
		ERR("Error registering key 512 [1024][2048][512]");
		goto done;
	}

	if ((result = disconnect_and_reconnect())) {
		ERR("Error reconnecting");
		goto done;
	}

	/* unregister the middle key again */
	if ((result = unregister_and_test(uuids[2], &key_handles[2]))) {
		ERR("Error testing key 2048 [1024][2048][512]");
		goto done;
	}

	/* re-register the middle key at the end */
	if ((result = Tspi_Context_RegisterKey(hContext, key_handles[2],
					       PS_TO_TEST, uuids[2],
					       TSS_PS_TYPE_SYSTEM, SRK_UUID))) {
		ERR("Error registering key 2048 [1024][512][2048]");
		goto done;
	}

	if ((result = disconnect_and_reconnect())) {
		ERR("Error reconnecting");
		goto done;
	}

	/* unregister the first again */
	if ((result = unregister_and_test(uuids[1], &key_handles[1]))) {
		ERR("Error testing key 1024 [1024][2048][512]");
		goto done;
	}

	/* re-register the middle key at the end */
	if ((result = Tspi_Context_RegisterKey(hContext, key_handles[1],
					       PS_TO_TEST, uuids[1],
					       TSS_PS_TYPE_SYSTEM, SRK_UUID))) {
		ERR("Error registering key 1024 [2048][512][1024]");
		goto done;
	}

	if ((result = disconnect_and_reconnect())) {
		ERR("Error reconnecting");
		goto done;
	}

	/* unregister the first again */
	if ((result = unregister_and_test(uuids[0], &key_handles[0]))) {
		ERR("Error testing key 512 [2048][512][1024]");
		goto done;
	}

	/* re-register the middle key at the end */
	if ((result = Tspi_Context_RegisterKey(hContext, key_handles[0],
					       PS_TO_TEST, uuids[0],
					       TSS_PS_TYPE_SYSTEM, SRK_UUID))) {
		ERR("Error registering key 512 [2048][1024][512]");
		goto done;
	}

done:
	for (i = 0; i < 3; i++)
		Tspi_Context_UnregisterKey(hContext, PS_TO_TEST, uuids[i], &hSRK);

	if (result) {
		print_error( "Tspi_Context_UnregisterKey", result );
	} else {
		print_success( function, result );
	}

	Tspi_Context_FreeMemory( hContext, NULL );
	Tspi_Context_Close( hContext );
}
