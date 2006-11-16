/*
 *
 *   Copyright (C) International Business Machines  Corp., 2005
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
 *	Tspi_Context_LoadKeyByBlob04.c
 *
 * DESCRIPTION
 *	This test will create 2 keys, one requiring auth and one not
 *  requiring auth. It will pull both key's blobs out and hold them in
 *  application memory, then close its TSP context and re-connect with
 *  a new one.  After reconnecting, it will call Tspi_Context_LoadKeyByBlob,
 *  attempt to use both keys with and without setting their policy secrets
 *  and will check that both keys are correct both in their software
 *  properties and in their usage through the TPM.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context
 *		Connect Context
 *		Load SRK by UUID
 *		Get Policy Object
 *		Set Secret
 *		Create Object (signing key)
 *		Create Key (signing key)
 *		Get Attrib Data (blob)
 *
 *	Test:
 *		Call Context_LoadKeyByBlob then if it does not succeed
 *		Make sure that it returns the proper return codes
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
 *	Kent Yoder, shpedoikal@gmail.com, 10/05
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
	char		*version;

	version = parseArgs( argc, argv );
		// if it is not version 1.1, print error
	if( strcmp(version, "1.1") )
		print_wrongVersion();
	else
		main_v1_1();
}

TSS_RESULT
verify_sign_attribs(TSS_HKEY hSigningKey)
{
	UINT32 attrib;
	TSS_RESULT result;

		// verify signing key's attribs
		// 1. Key Type
	if ((result = Tspi_GetAttribUint32(hSigningKey,
					   TSS_TSPATTRIB_KEY_INFO,
					   TSS_TSPATTRIB_KEYINFO_USAGE,
					   &attrib))) {
		print_error( "Tspi_GetAttribUint32", result );
		return result;
	}
	if (attrib != TSS_KEYUSAGE_SIGN) {
		print_verifyerr("key usage", TSS_KEYUSAGE_SIGN, attrib);
		return TSS_E_FAIL;
	}

		// 2. Auth data usage
	if ((result = Tspi_GetAttribUint32(hSigningKey,
					   TSS_TSPATTRIB_KEY_INFO,
					   TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE,
					   &attrib))) {
		print_error( "Tspi_GetAttribUint32", result );
		return result;
	}
	if (attrib != FALSE) {
		print_verifyerr("key authdata usage", FALSE, attrib);
		return TSS_E_FAIL;
	}
		// 3. Key size
	if ((result = Tspi_GetAttribUint32(hSigningKey,
					   TSS_TSPATTRIB_RSAKEY_INFO,
					   TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE,
					   &attrib))) {
		print_error( "Tspi_GetAttribUint32", result );
		return result;
	}
	if (attrib != TSS_KEY_SIZEVAL_2048BIT) {
		print_verifyerr("key size", TSS_KEY_SIZEVAL_2048BIT, attrib);
		return TSS_E_FAIL;
	}

	return result;
}

TSS_RESULT
verify_bind_attribs(TSS_HKEY hBindingKey)
{
	UINT32 attrib;
	TSS_RESULT result;

		// verify binding key's attribs
		// 1. Key Type
	if ((result = Tspi_GetAttribUint32(hBindingKey,
					   TSS_TSPATTRIB_KEY_INFO,
					   TSS_TSPATTRIB_KEYINFO_USAGE,
					   &attrib))) {
		print_error( "Tspi_GetAttribUint32", result );
		return result;
	}
	if (attrib != TSS_KEYUSAGE_BIND) {
		print_verifyerr("key usage", TSS_KEYUSAGE_BIND, attrib);
		return TSS_E_FAIL;
	}

		// 2. Auth data usage
	if ((result = Tspi_GetAttribUint32(hBindingKey,
					   TSS_TSPATTRIB_KEY_INFO,
					   TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE,
					   &attrib))) {
		print_error( "Tspi_GetAttribUint32", result );
		return result;
	}
	if (attrib != TRUE) {
		print_verifyerr("key authdata usage", TRUE, attrib);
		return TSS_E_FAIL;
	}

		// 3. Key size
	if ((result = Tspi_GetAttribUint32(hBindingKey,
					   TSS_TSPATTRIB_RSAKEY_INFO,
					   TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE,
					   &attrib))) {
		print_error( "Tspi_GetAttribUint32", result );
		return result;
	}
	if (attrib != TSS_KEY_SIZEVAL_2048BIT) {
		print_verifyerr("key size", TSS_KEY_SIZEVAL_2048BIT, attrib);
		return TSS_E_FAIL;
	}

	return result;
}

int
main_v1_1( void )
{
	char		*function = "Tspi_Context_LoadKeyByBlob04";
	TSS_HCONTEXT	hContext;
	TSS_HKEY	hSRK, hSigningKey, hBindingKey;
	TSS_HPOLICY	hPolicy;
	TSS_RESULT	result;
	UINT32		exitCode, attrib;
	TSS_FLAG	initFlags;
	BYTE		*signBlob, *bindBlob;
	UINT32		signBlobLen, bindBlobLen;

	print_begin_test( function );

		// Create Context
	if ((result = connect_load_srk(&hContext, &hSRK))) {
		print_error( "connect_load_srk", result );
		print_error_exit( function, err_string(result) );
		exit( result );
	}

		// create a no-auth, signing key
	initFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 |
		    TSS_KEY_NO_AUTHORIZATION;
	if ((result = create_load_key(hContext, initFlags, hSRK, &hSigningKey))) {
		print_error( "create_load_key(Signing Key)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	print_success("Signing key created successfully", TSS_SUCCESS);

		// get blob
	result = Tspi_GetAttribData( hSigningKey, TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_BLOB,
					&signBlobLen, &signBlob );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetAttribData", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// create a auth, binding key
	initFlags = TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048 |
		    TSS_KEY_AUTHORIZATION;
	if ((result = create_load_key(hContext, initFlags, hSRK, &hBindingKey))) {
		print_error( "create_load_key(Binding Key)", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	print_success("Binding key created successfully", TSS_SUCCESS);

		// get blob
	result = Tspi_GetAttribData( hBindingKey, TSS_TSPATTRIB_KEY_BLOB,
					TSS_TSPATTRIB_KEYBLOB_BLOB,
					&bindBlobLen, &bindBlob );
	if ( result != TSS_SUCCESS )
	{
		print_error( "Tspi_GetAttribData", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	// verify attribs before we close the context
	if ((result = verify_sign_attribs(hSigningKey))) {
		print_error( "verify_sign_attribs", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	// verify attribs before we close the context
	if ((result = verify_bind_attribs(hBindingKey))) {
		print_error( "verify_bind_attribs", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// close context, to get rid of all context state
	if ((result = Tspi_Context_Close(hContext))) {
		print_error( "Tspi_Context_Close", result );
		print_error_exit( function, err_string(result) );
		exit( result );
	}

		// re-connect
	if ((result = connect_load_srk(&hContext, &hSRK))) {
		print_error( "connect_load_srk", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

		// Load both Keys by blob
	if ((result = Tspi_Context_LoadKeyByBlob( hContext, hSRK,
						signBlobLen,
						signBlob,
						&hSigningKey ))) {
		print_error( "Tspi_Context_LoadKeyByBlob", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}
	if ((result = Tspi_Context_LoadKeyByBlob( hContext, hSRK,
						bindBlobLen,
						bindBlob,
						&hBindingKey ))) {
		print_error( "Tspi_Context_LoadKeyByBlob", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	// verify attribs after we've re-loaded by blob
	if ((result = verify_sign_attribs(hSigningKey))) {
		print_error( "verify_sign_attribs", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	// verify attribs after we've re-loaded by blob
	if ((result = verify_bind_attribs(hBindingKey))) {
		print_error( "verify_bind_attribs", result );
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}


	// Do a sign/verify test
	if ((result = sign_and_verify(hContext, hSigningKey))) {
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}


	// Do a bind/unbind test
	result = bind_and_unbind(hContext, hBindingKey);
	if (TSS_ERROR_CODE(result) != TSS_E_POLICY_NO_SECRET) {
		print_verifyerr("bind and unbind", TSS_E_POLICY_NO_SECRET, result);
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	// set up policies
	if ((result = set_secret(hBindingKey, &hPolicy))) {
		print_error_exit(function, err_string(result));
		Tspi_Context_Close( hContext );
		exit( result );
	}

	if ((result = bind_and_unbind(hContext, hBindingKey))) {
		print_error_exit( function, err_string(result) );
		Tspi_Context_Close( hContext );
		exit( result );
	}

	exitCode = 0;
	print_success(function, TSS_SUCCESS);
	print_end_test( function );
	Tspi_Context_Close( hContext );
	exit( exitCode );
}
