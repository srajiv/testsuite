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
 *	Tspi_TPM_CreateIdentity.c
 *
 * DESCRIPTION
 *	This test will attempt to act as a PrivacyCA and create a TPM
 *	identity.
 *
 * ALGORITHM
 *	Setup:
 *		Create Context, load the SRK and get a TPM handle
 *		Generate an openssl RSA key to represent the CA's key
 *		Create the identity key's object
 *		Call Tspi_TPM_CollateIdentityRequest
 *		Decrypt the symmetric and asymmetric blobs
 *		Verify the identity binding
 *		Create a fake credential and encrypt it
 *		Call Tspi_TPM_ActivateIdentity
 *	Test:
 *		Compare the returned credential to the one we passed in
 *
 *	Cleanup:
 *		Free memory associated with the context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1
 *
 * HISTORY
 *	Kent Yoder, kyoder@users.sf.net
 *
 * RESTRICTIONS
 *	None.
 */

#include <limits.h>

#include "common.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#define CA_KEY_SIZE_BITS 2048

#define CERT_VERIFY_BYTE 0x5a

TCPA_ALGORITHM_ID symAlg = TCPA_ALG_3DES;
TSS_ALGORITHM_ID tssSymAlg = TSS_ALG_3DES;

/* substitute this for TPM_IDENTITY_CREDENTIAL in the TPM docs */
struct trousers_ca_tpm_identity_credential
{
	/* This should be set up according to the TPM 1.1b spec section
	 * 9.5.5.  For now, just use it to verify we got the right stuff
	 * back from the activate identity call. */
	X509 cert;
} ca_cred;

/* helper struct for passing stuff from function to function */
struct ca_blobs
{
	UINT32 asymBlobSize, symBlobSize;
	BYTE *asymBlob;
	BYTE *symBlob;
};

const char *fn = "Tspi_TPM_CreateIdentity";

TSS_RESULT
ca_setup_key(TSS_HCONTEXT hContext, TSS_HKEY *hCAKey, RSA **rsa, int padding)
{
	TSS_RESULT result;
	UINT32 encScheme, size_n;
	BYTE n[2048];

	switch (padding) {
		case RSA_PKCS1_PADDING:
			encScheme = TSS_ES_RSAESPKCSV15;
			break;
		case RSA_PKCS1_OAEP_PADDING:
			encScheme = TSS_ES_RSAESOAEP_SHA1_MGF1;
			break;
		case RSA_NO_PADDING:
			encScheme = TSS_ES_NONE;
			break;
		default:
			return TSS_E_INTERNAL_ERROR;
			break;
	}

		//Create CA Key Object
	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_2048,
					   hCAKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		return result;
	}

		// generate a software key to represent the CA's key
	if ((*rsa = RSA_generate_key(CA_KEY_SIZE_BITS, 65537, NULL, NULL)) == NULL) {
		ERR_print_errors_fp(stdout);
		return result;
	}

		// get the pub CA key
	if ((size_n = BN_bn2bin((*rsa)->n, n)) <= 0) {
		fprintf(stderr, "BN_bn2bin failed\n");
		ERR_print_errors_fp(stdout);
		RSA_free(*rsa);
                return 254; // ?
        }

	result = set_public_modulus(hContext, *hCAKey, size_n, n);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_SetAttribData ", result);
		RSA_free(*rsa);
		return result;
	}

		// set the CA key's algorithm
	result = Tspi_SetAttribUint32(*hCAKey, TSS_TSPATTRIB_KEY_INFO,
				      TSS_TSPATTRIB_KEYINFO_ALGORITHM,
				      TSS_ALG_RSA);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_SetAttribUint32", result);
		RSA_free(*rsa);
		return result;
	}

		// set the CA key's number of primes
	result = Tspi_SetAttribUint32(*hCAKey, TSS_TSPATTRIB_RSAKEY_INFO,
				      TSS_TSPATTRIB_KEYINFO_RSA_PRIMES,
				      2);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_SetAttribUint32", result);
		RSA_free(*rsa);
		return result;
	}

		// set the CA key's encryption scheme
	result = Tspi_SetAttribUint32(*hCAKey, TSS_TSPATTRIB_KEY_INFO,
				      TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
				      encScheme);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_SetAttribUint32", result);
		RSA_free(*rsa);
		return result;
	}

	return TSS_SUCCESS;
}

/* The identity binding is the following:
 * Sign_AIK(SHA1(label || TCPA_PUBKEY(CApub)))
 */
TSS_RESULT
ca_verify_identity_binding(TSS_HCONTEXT hContext, TSS_HTPM hTPM,
			   TSS_HKEY hCAKey, TSS_HKEY hIdentityKey,
			   TCPA_IDENTITY_PROOF *proof)
{
	TSS_RESULT result;
	BYTE blob[2048];
	UINT16 offset;
	TCPA_KEY key;
	TCPA_DIGEST digest, chosenId;
	UINT32 keyBlobSize, subCap = TSS_TPMCAP_VERSION, versionSize;
	BYTE *keyBlob;
	TSS_HHASH hHash;
	BYTE *versionBlob;

	if ((result = Tspi_Context_CreateObject(hContext,
						TSS_OBJECT_TYPE_HASH,
						TSS_HASH_SHA1, &hHash))) {
		print_error("Tspi_Context_CreateObject", result);
		return result;
	}

	if ((result = Tspi_GetAttribData(hCAKey, TSS_TSPATTRIB_KEY_BLOB,
					 TSS_TSPATTRIB_KEYBLOB_BLOB,
					 &keyBlobSize, &keyBlob))) {
		print_error("Tspi_GetAttribData", result);
		return result;
	}

	offset = 0;
	if ((result = TestSuite_UnloadBlob_KEY(&offset, keyBlob, &key))) {
		print_error("TestSuite_UnloadBlob_KEY", result);
		return result;
	}

	Tspi_Context_FreeMemory(hContext, keyBlob);

	/* make the chosen id hash */
	offset = 0;
	TestSuite_LoadBlob(&offset, proof->labelSize, blob, proof->labelArea);
	TestSuite_LoadBlob_KEY_PARMS(&offset, blob, &key.algorithmParms);
	TestSuite_LoadBlob_STORE_PUBKEY(&offset, blob, &key.pubKey);

	if ((result = TestSuite_Hash(TSS_HASH_SHA1, offset, blob,
				 (BYTE *)&chosenId.digest)))
		return result;

	if ((result = Tspi_TPM_GetCapability(hTPM, TSS_TPMCAP_VERSION,
					     0, NULL, &versionSize,
					     &versionBlob))) {
		print_error("Tspi_TPM_GetCapability", result);
		return result;
	}
#ifndef TPM_ORD_MakeIdentity
#define TPM_ORD_MakeIdentity 121
#endif

	offset = 0;
	TestSuite_LoadBlob(&offset, versionSize, blob, versionBlob);
	TestSuite_LoadBlob_UINT32(&offset, TPM_ORD_MakeIdentity, blob);
	TestSuite_LoadBlob(&offset, 20, blob, (BYTE *)&chosenId.digest);
	TestSuite_LoadBlob_PUBKEY(&offset, blob, &proof->identityKey);

	free(key.algorithmParms.parms);
	free(key.pubKey.key);
	free(key.encData);
	free(key.PCRInfo);

	if ((result = TestSuite_Hash(TSS_HASH_SHA1, offset, blob,
				 (BYTE *)&digest.digest)))
		return result;

	if ((result = Tspi_Hash_SetHashValue(hHash, 20, (BYTE *)&digest.digest))) {
		print_error("Tspi_Hash_SetHashValue", result);
		return result;
	}

	return Tspi_Hash_VerifySignature(hHash, hIdentityKey,
					 proof->identityBindingSize,
					 proof->identityBinding);
}

TSS_RESULT
ca_create_credential(TSS_HCONTEXT hContext, TSS_HTPM hTPM,
		     TSS_HKEY hIdentityKey, struct ca_blobs *b)
{
	TCPA_SYM_CA_ATTESTATION symAttestation;
	TCPA_ASYM_CA_CONTENTS asymContents;
	BYTE blob[2048], blob2[2048];
	BYTE *identityBlob;
	UINT32 identityBlobSize, blobSize = 2048, blob2Size = 2048;
	TCPA_KEY idKey;
	UINT16 offset;
	TSS_HKEY hPubEK;
	TSS_HENCDATA hEncData;
	TSS_RESULT result;
	BYTE *pubEK;
	UINT32 pubEKSize, tmpblobsize = 0x2000, i;
	BYTE tmpblob[0x2000];

	if ((result = Tspi_TPM_GetPubEndorsementKey(hTPM, TRUE, NULL,
						    &hPubEK))) {
		print_error("Tspi_TPM_GetPubEndorsementKey", result);
		return result;
	}

	if ((result = Tspi_Context_CreateObject(hContext,
						TSS_OBJECT_TYPE_ENCDATA,
						TSS_ENCDATA_BIND,
						&hEncData))) {
		print_error("Tspi_Context_CreateObject", result);
		return result;
	}

	/* fill out the asym contents structure */
	asymContents.sessionKey.algId = symAlg;
	asymContents.sessionKey.encScheme = TCPA_ES_NONE;

	switch (asymContents.sessionKey.algId) {
		case TCPA_ALG_AES:
			asymContents.sessionKey.size = 128/8;
			break;
		case TCPA_ALG_DES:
			asymContents.sessionKey.size = 64/8;
			break;
		case TCPA_ALG_3DES:
			asymContents.sessionKey.size = 192/8;
			break;
		default:
			print_error("Invalid symmetric algorithm!", -1);
			return TSS_E_INTERNAL_ERROR;
	}

	if ((result = Tspi_TPM_GetRandom(hTPM, asymContents.sessionKey.size,
					 &asymContents.sessionKey.data))) {
		print_error("Tspi_TPM_GetRandom", result);
		return result;
	}

	/* TPM 1.1b spec pg. 277 step 4 says "digest of the public key of
	 * idKey"...  I'm assuming that this is a TCPA_PUBKEY */
	if ((result = Tspi_GetAttribData(hIdentityKey,
					 TSS_TSPATTRIB_KEY_BLOB,
					 TSS_TSPATTRIB_KEYBLOB_BLOB,
					 &identityBlobSize,
					 &identityBlob))) {
		print_error("Tspi_GetAttribData", result);
		Tspi_Context_FreeMemory(hContext,
					asymContents.sessionKey.data);
		return result;
	}

	offset = 0;
	if ((result = TestSuite_UnloadBlob_KEY(&offset, identityBlob, &idKey))) {
		print_error("TestSuite_UnloadBlob_KEY", result);
		return result;
	}

	offset = 0;
	TestSuite_LoadBlob_KEY_PARMS(&offset, blob, &idKey.algorithmParms);
	TestSuite_LoadBlob_STORE_PUBKEY(&offset, blob, &idKey.pubKey);
	TestSuite_Hash(TSS_HASH_SHA1, offset, blob,
		   (BYTE *)&asymContents.idDigest.digest);

	/* create the TCPA_SYM_CA_ATTESTATION structure */
	symAttestation.algorithm.algorithmID = symAlg;
	symAttestation.algorithm.encScheme = TCPA_ES_NONE;
	symAttestation.algorithm.sigScheme = 0;
	symAttestation.algorithm.parmSize = 0;
	symAttestation.algorithm.parms = NULL;

	/* set the credential to something known before encrypting it
	 * so that we can compare the credential that the TSS returns to
	 * something other than all 0's */
	memset(&ca_cred, CERT_VERIFY_BYTE, sizeof(struct trousers_ca_tpm_identity_credential));

	/* encrypt the credential w/ the sym key */
	if ((result = TestSuite_SymEncrypt(symAlg, TCPA_ES_NONE, asymContents.sessionKey.data, NULL,
					   (BYTE *)&ca_cred,
					   sizeof(struct trousers_ca_tpm_identity_credential),
					   blob2, &blob2Size))) {
		print_error("TestSuite_SymEncrypt", result);
		Tspi_Context_FreeMemory(hContext, asymContents.sessionKey.data);
		return result;
	}

	/* blob2 now contains the encrypted credential, which is part of the TCPA_SYM_CA_ATTESTATION
	 * structure that we'll pass into ActivateIdentity. */
	symAttestation.credential = blob2;
	symAttestation.credSize = blob2Size;
	offset = 0;
	TestSuite_LoadBlob_SYM_CA_ATTESTATION(&offset, blob, &symAttestation);

	/* blob now contains the serialized TCPA_SYM_CA_ATTESTATION struct */
	if ((b->symBlob = malloc(offset)) == NULL) {
		fprintf(stderr, "malloc failed.");
		Tspi_Context_FreeMemory(hContext, asymContents.sessionKey.data);
		return TSS_E_OUTOFMEMORY;
	}

	memcpy(b->symBlob, blob, offset);
	b->symBlobSize = offset;

	/* encrypt the TCPA_ASYM_CA_CONTENTS blob with the TPM's PubEK */
	offset = 0;
	TestSuite_LoadBlob_ASYM_CA_CONTENTS(&offset, blob, &asymContents);

	/* free the malloc'd structure member now that its in the blob */
	Tspi_Context_FreeMemory(hContext, asymContents.sessionKey.data);
	if ((result = Tspi_GetAttribData(hPubEK, TSS_TSPATTRIB_RSAKEY_INFO,
					TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
					&pubEKSize, &pubEK))) {
		free(b->symBlob);
		b->symBlob = NULL;
		b->symBlobSize = 0;
		return result;
	}

	/* encrypt using the TPM's custom OAEP padding parameter */
	if ((result = TestSuite_TPM_RSA_Encrypt(blob, offset, tmpblob,
						&tmpblobsize, pubEK,
						pubEKSize))) {
		Tspi_Context_FreeMemory(hContext, pubEK);
		free(b->symBlob);
		b->symBlob = NULL;
		b->symBlobSize = 0;
		return result;
	}

	Tspi_Context_FreeMemory(hContext, pubEK);

	if ((b->asymBlob = malloc(tmpblobsize)) == NULL) {
		free(b->symBlob);
		b->symBlob = NULL;
		b->symBlobSize = 0;
		return TSS_E_OUTOFMEMORY;
	}

	memcpy(b->asymBlob, tmpblob, tmpblobsize);
	b->asymBlobSize = tmpblobsize;

	return TSS_SUCCESS;
}

int
main(int argc, char **argv)
{
	char version;

	version = parseArgs( argc, argv );
	if (version)
		main_v1_1();
	else
		print_wrongVersion();
}

main_v1_1(void){

	TSS_HCONTEXT		hContext;
	TSS_HTPM		hTPM;
	TSS_FLAG		initFlags;
	TSS_HKEY		hSRK, hIdentKey, hCAKey;
	TSS_HPOLICY		hTPMPolicy, hIdPolicy;
	TSS_RESULT		result;
	RSA			*rsa = NULL;
	BYTE			*rgbIdentityLabelData = NULL, *identityReqBlob;
	BYTE			*labelString = "My Identity Label";
	UINT32			labelLen = strlen(labelString) + 1;
	UINT32			ulIdentityReqBlobLen, utilityBlobSize, credLen;
	UINT16			offset;
	TCPA_IDENTITY_REQ	identityReq;
	TCPA_IDENTITY_PROOF	identityProof;
	TCPA_SYMMETRIC_KEY	symKey;
	TCPA_ALGORITHM_ID	algID;
	TCPA_SYM_CA_ATTESTATION symAttestation;
	BYTE			utilityBlob[USHRT_MAX], *cred;
	int			padding = RSA_PKCS1_OAEP_PADDING, tmp;
	struct ca_blobs		b;

	initFlags	= TSS_KEY_TYPE_IDENTITY | TSS_KEY_SIZE_2048  |
			TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
			TSS_KEY_NOT_MIGRATABLE;

	print_begin_test(fn);

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

		//Create Context
	result = connect_load_all(&hContext, &hSRK, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("connect_load_all", result);
		print_error_exit(fn, err_string(result));
		exit(result);
	}

		//Insert the owner auth into the TPM's policy
	result = Tspi_GetPolicyObject(hTPM, TSS_POLICY_USAGE, &hTPMPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(fn, err_string(result));
		exit(result);
	}

	result = Tspi_Policy_SetSecret(hTPMPolicy, TESTSUITE_OWNER_SECRET_MODE,
				       TESTSUITE_OWNER_SECRET_LEN, TESTSUITE_OWNER_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(fn, err_string(result));
		exit(result);
	}

		//Create Identity Key Object
	result = Tspi_Context_CreateObject(hContext,
					   TSS_OBJECT_TYPE_RSAKEY,
					   initFlags, &hIdentKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(fn, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

		//Insert the auth into the identity key's policy
	result = Tspi_GetPolicyObject(hIdentKey, TSS_POLICY_USAGE, &hIdPolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(fn, err_string(result));
		exit(result);
	}

	result = Tspi_Policy_SetSecret(hIdPolicy, TESTSUITE_KEY_SECRET_MODE,
				       TESTSUITE_KEY_SECRET_LEN, TESTSUITE_KEY_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(fn, err_string(result));
		exit(result);
	}

	result = ca_setup_key(hContext, &hCAKey, &rsa, padding);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(fn, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	rgbIdentityLabelData = TestSuite_Native_To_UNICODE(labelString, &labelLen);
	if (rgbIdentityLabelData == NULL) {
		fprintf(stderr, "TestSuite_Native_To_UNICODE failed\n");
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
                exit(result);
	}

	result = Tspi_TPM_CollateIdentityRequest(hTPM, hSRK, hCAKey, labelLen,
						 rgbIdentityLabelData,
						 hIdentKey, tssSymAlg,
						 &ulIdentityReqBlobLen,
						 &identityReqBlob);
	if (result != TSS_SUCCESS){
		print_error("Tspi_TPM_CollateIdentityRequest", result);
		print_error_exit(fn, err_string(result));
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}


	/* decrypt the TCPA_IDENTITY_REQ blobs */
	offset = 0;
	if ((result = TestSuite_UnloadBlob_IDENTITY_REQ(&offset,
						    identityReqBlob,
						    &identityReq))) {
		print_error("TestSuite_UnloadBlob_IDENTITY_REQ", result);
		print_error_exit(fn, err_string(result));
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}

	if ((tmp = RSA_private_decrypt(identityReq.asymSize,
				       identityReq.asymBlob,
				       utilityBlob,
				       rsa, padding)) <= 0) {
		print_error("RSA_private_decrypt", result);
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}

	offset = 0;
	if ((result = TestSuite_UnloadBlob_SYMMETRIC_KEY(&offset, utilityBlob,
						     &symKey))) {
		print_error("TestSuite_UnloadBlob_SYMMETRIC_KEY", result);
		print_error_exit(fn, err_string(result));
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}

	switch (symKey.algId) {
		case TCPA_ALG_DES:
			algID = TSS_ALG_DES;
			break;
		case TCPA_ALG_3DES:
			algID = TSS_ALG_3DES;
			break;
		case TCPA_ALG_AES:
			algID = TSS_ALG_AES;
			break;
		default:
			fprintf(stderr, "symmetric blob encrypted with an "
				"unknown cipher\n");
			Tspi_Context_Close(hContext);
			RSA_free(rsa);
			exit(result);
			break;
	}

	utilityBlobSize = sizeof(utilityBlob);
	if ((result = TestSuite_SymDecrypt(algID, symKey.encScheme, symKey.data, NULL,
				       identityReq.symBlob, identityReq.symSize, utilityBlob,
				       &utilityBlobSize))) {
		print_error("TestSuite_SymDecrypt", result);
		print_error_exit(fn, err_string(result));
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}

	offset = 0;
	if ((result = TestSuite_UnloadBlob_IDENTITY_PROOF(&offset, utilityBlob,
						      &identityProof))) {
		print_error("TestSuite_UnloadBlob_IDENTITY_PROOF", result);
		print_error_exit(fn, err_string(result));
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}

	/* verify the identity binding */
	if ((result = ca_verify_identity_binding(hContext, hTPM, hCAKey,
						 hIdentKey, &identityProof))) {
		if (TSS_ERROR_CODE(result) == TSS_E_FAIL)
			fprintf(stderr, "Identity Binding signature doesn't "
				"match!\n");
		print_error_exit(fn, err_string(result));
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}

	/* binding is verified, load the identity key into the TPM */
	if ((result = Tspi_Key_LoadKey(hIdentKey, hSRK))) {
		print_error_exit(fn, err_string(result));
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}

	/* verify the EK's credentials in the identity proof structure */
	/* XXX Doesn't yet exist. In 1.2 they should be in NVDATA somewhere */

	if ((result = ca_create_credential(hContext, hTPM, hIdentKey, &b))) {
		print_error_exit(fn, err_string(result));
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}

	/* activate the TPM identity, receiving back the decrypted
	 * credential */
	result = Tspi_TPM_ActivateIdentity(hTPM, hIdentKey, b.asymBlobSize,
					   b.asymBlob, b.symBlobSize,
					   b.symBlob, &credLen, &cred);

	if (result) {
		print_error("Tspi_TPM_ActivateIdentity", result);
		print_error_exit(fn, err_string(result));
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}
#if 0
	offset = 0;
	if ((result = TestSuite_UnloadBlob_SYM_CA_ATTESTATION(&offset, cred,
							  &symAttestation))) {
		print_error_exit(fn, err_string(result));
		Tspi_Context_Close(hContext);
		RSA_free(rsa);
		exit(result);
	}

	Tspi_Context_FreeMemory(hContext, cred);

	/* verify that the credential is the same */
	if (symAttestation.credSize == sizeof(ca_cred) &&
	    !memcmp(symAttestation.credential, &ca_cred,
		    symAttestation.credSize)) {
		print_success(fn, result );
	} else {
		fprintf(stderr, "credential doesn't match!\n");
		print_error_exit(fn, err_string(TCPA_E_FAIL));
	}
#else
	/* verify that the credential is the same */
	if (credLen == sizeof(ca_cred) && !memcmp(cred, &ca_cred, credLen)) {
		print_success(fn, result );
	} else {
		fprintf(stderr, "credential doesn't match!\n");
		print_error_exit(fn, err_string(TCPA_E_FAIL));
	}
#endif

	Tspi_Context_Close(hContext);
	RSA_free(rsa);

	return 0;
}
